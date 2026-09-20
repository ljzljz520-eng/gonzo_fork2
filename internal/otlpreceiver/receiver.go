package otlpreceiver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	otlpgrpc "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/control-theory/gonzo/internal/security"
)

// Sink is the alias for the security package's ingest interface: the
// command wiring converts authenticated requests to log entries and indexes
// them per tenant.
type Sink = security.Sink

// Receiver is the secured OTLP logs receiver. Every request flows through:
//
//	transport (mTLS / loopback TCP / Unix socket)
//	  → authenticator (SPIFFE / OIDC / API token / SO_PEERCRED)
//	  → per-tenant quota (size, rate, cardinality)
//	  → per-tenant bounded parse queue (fair scheduler, isolated backlog)
//	  → sink (trusted attribute stamping, conversion, tenant-scoped index)
type Receiver struct {
	cfg       *security.Config
	auth      *security.Authenticator
	limiter   *security.Limiter
	scheduler *security.Scheduler
	rejects   *security.RejectLogger
	sink      Sink
	workers   int

	otlpgrpc.UnimplementedLogsServiceServer

	grpcServer *grpc.Server
	httpServer *http.Server // TCP HTTP surface (TLS when configured)
	uxServer   *http.Server // Unix socket: h2c gRPC + HTTP/1.1 multiplexed

	listeners []net.Listener

	jsonMarshaler   protojson.MarshalOptions
	jsonUnmarshaler protojson.UnmarshalOptions

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

// Option configures optional receiver parameters.
type Option func(*Receiver)

// WithWorkers overrides the parse worker pool size.
func WithWorkers(n int) Option {
	return func(r *Receiver) { r.workers = n }
}

// WithLimiter injects an externally constructed limiter so the same
// per-tenant limits (rate, cardinality, storage) are shared with the engine
// and other surfaces. When omitted the receiver builds its own.
func WithLimiter(l *security.Limiter) Option {
	return func(r *Receiver) {
		if l != nil {
			r.limiter = l
		}
	}
}

// Limiter exposes the effective limiter (used after Start for diagnostics).
func (r *Receiver) Limiter() *security.Limiter { return r.limiter }

// New builds a secured receiver. Call Start to begin serving.
func New(cfg *security.Config, sink Sink, rejects *security.RejectLogger, opts ...Option) (*Receiver, error) {
	if cfg == nil {
		return nil, errors.New("nil security config")
	}
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	auth, err := security.NewAuthenticator(cfg, rejects)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Receiver{
		cfg:     cfg,
		auth:    auth,
		limiter: security.NewLimiter(cfg, rejects),
		rejects: rejects,
		sink:    sink,
		ctx:     ctx,
		cancel:  cancel,
		jsonMarshaler: protojson.MarshalOptions{
			UseProtoNames: true,
		},
		jsonUnmarshaler: protojson.UnmarshalOptions{
			DiscardUnknown: true,
		},
	}
	for _, opt := range opts {
		opt(r)
	}
	r.scheduler = security.NewScheduler(ctx, r.limiter, sink, rejects, r.workers)
	return r, nil
}

// Start opens all configured listeners.
func (r *Receiver) Start() error {
	if err := r.validateListenSurface(); err != nil {
		return err
	}
	var tlsCfg *tls.Config
	if r.cfg.TLS != nil {
		t, tlsErr := security.BuildServerTLSConfig(r.cfg.TLS)
		if tlsErr != nil {
			return tlsErr
		}
		tlsCfg = t
	}

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/v1/logs", r.handleHTTPLogs)
	authedMux := r.auth.HTTPMiddleware("http", httpMux)

	// gRPC surface (TCP). The same grpc.Server is also served over the
	// Unix socket via h2c multiplexing, so interceptors protect both.
	{
		var grpcOpts []grpc.ServerOption
		grpcOpts = append(grpcOpts,
			grpc.MaxRecvMsgSize(security.HardMaxMessageBytes),
			grpc.MaxSendMsgSize(security.HardMaxMessageBytes),
			grpc.ChainUnaryInterceptor(r.auth.GRPCUnaryInterceptor, r.grpcQuotaInterceptor),
			grpc.ChainStreamInterceptor(r.auth.GRPCStreamInterceptor),
		)
		if tlsCfg != nil {
			grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		}
		r.grpcServer = grpc.NewServer(grpcOpts...)
		otlpgrpc.RegisterLogsServiceServer(r.grpcServer, r)
	}

	// TCP HTTP surface.
	r.httpServer = &http.Server{
		Handler:           authedMux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if tlsCfg != nil {
		r.httpServer.TLSConfig = tlsCfg
	}

	// TCP gRPC listener.
	if r.cfg.GRPCAddr != "" {
		ln, err := net.Listen("tcp", r.cfg.GRPCAddr)
		if err != nil {
			r.closeAll()
			return fmt.Errorf("listen gRPC %s: %w", r.cfg.GRPCAddr, err)
		}
		r.listeners = append(r.listeners, ln)
		r.serveGRPC(ln, "grpc-tcp")
		log.Printf("OTLP gRPC receiver listening on %s%s", r.cfg.GRPCAddr, tlsLabel(tlsCfg))
	}

	// TCP HTTP listener.
	if r.cfg.HTTPAddr != "" {
		ln, err := net.Listen("tcp", r.cfg.HTTPAddr)
		if err != nil {
			r.closeAll()
			return fmt.Errorf("listen HTTP %s: %w", r.cfg.HTTPAddr, err)
		}
		r.listeners = append(r.listeners, ln)
		r.serveHTTP(r.httpServer, ln, tlsCfg != nil, "http-tcp")
		log.Printf("OTLP HTTP receiver listening on %s%s", r.cfg.HTTPAddr, tlsLabel(tlsCfg))
	}

	// Unix domain socket: one socket multiplexes h2c gRPC and HTTP/1.1
	// OTLP/JSON. Identity comes from kernel peer credentials.
	if r.cfg.UnixSocket != "" {
		ln, err := security.ListenUnix(r.cfg.UnixSocket, r.cfg.UnixSocketMode)
		if err != nil {
			r.closeAll()
			return err
		}
		r.listeners = append(r.listeners, ln)
		r.uxServer = &http.Server{
			Handler:           r.unixMux(authedMux),
			ReadHeaderTimeout: 10 * time.Second,
		}
		r.serveHTTP(r.uxServer, ln, false, "unix")
		log.Printf("OTLP receiver listening on unix socket %s (mode %s, gRPC+HTTP)",
			r.cfg.UnixSocket, r.cfg.UnixSocketMode)
	}

	r.scheduler.Start()
	return nil
}

// unixMux routes h2c gRPC traffic to the grpc.Server (its interceptors
// extract SO_PEERCRED-derived identity from the peer address) and everything
// else to the authenticated OTLP HTTP mux.
func (r *Receiver) unixMux(httpHandler http.Handler) http.Handler {
	h2s := &http2.Server{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.ProtoMajor == 2 && isGRPCPath(req.URL.Path) {
			r.grpcServer.ServeHTTP(w, req)
			return
		}
		httpHandler.ServeHTTP(w, req)
	})
	return h2c.NewHandler(handler, h2s)
}

func isGRPCPath(path string) bool {
	return strings.Contains(path, "LogsService/")
}

func tlsLabel(s *tls.Config) string {
	if s == nil {
		return " (plaintext; loopback/UDS only — use mTLS for network access)"
	}
	return " (mTLS, client cert required)"
}

func (r *Receiver) serveGRPC(ln net.Listener, name string) {
	r.wg.Go(func() {
		if err := r.grpcServer.Serve(ln); err != nil && err != grpc.ErrServerStopped {
			log.Printf("OTLP %s serve error: %v", name, err)
		}
	})
}

func (r *Receiver) serveHTTP(srv *http.Server, ln net.Listener, useTLS bool, name string) {
	r.wg.Go(func() {
		var err error
		if useTLS {
			err = srv.ServeTLS(ln, "", "")
		} else {
			err = srv.Serve(ln)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("OTLP %s serve error: %v", name, err)
		}
	})
}

// validateListenSurface refuses insecure non-loopback TCP: unauthenticated
// injection over the network is the exact footgun this receiver exists to
// prevent. Operators must configure mTLS/OIDC/tokens, bind loopback, or use
// a Unix socket.
func (r *Receiver) validateListenSurface() error {
	authConfigured := r.cfg.TLS != nil || r.cfg.OIDC != nil || len(r.cfg.APITokens) > 0
	if authConfigured || r.cfg.ObserveOnly {
		return nil
	}
	for _, addr := range []string{r.cfg.GRPCAddr, r.cfg.HTTPAddr} {
		if addr == "" {
			continue
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("invalid listen address %q: %w", addr, err)
		}
		if host != "" && host != "127.0.0.1" && host != "::1" && host != "localhost" {
			return fmt.Errorf("refusing to bind %q without authentication: configure mTLS (spiffe), OIDC or api-tokens, use a loopback address, or a unix socket", addr)
		}
	}
	return nil
}

func (r *Receiver) closeAll() {
	for _, ln := range r.listeners {
		_ = ln.Close()
	}
}

// Stop gracefully shuts all surfaces down.
func (r *Receiver) Stop() {
	r.cancel()
	if r.grpcServer != nil {
		r.grpcServer.GracefulStop()
	}
	for _, srv := range []*http.Server{r.httpServer, r.uxServer} {
		if srv == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
	}
	for _, ln := range r.listeners {
		_ = ln.Close()
	}
	r.wg.Wait()
}

// Export is the OTLP service implementation. It is unreachable in normal
// operation because grpcQuotaInterceptor short-circuits after admission; it
// exists to satisfy the service registration and fails closed.
func (r *Receiver) Export(context.Context, *otlpgrpc.ExportLogsServiceRequest) (*otlpgrpc.ExportLogsServiceResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "request bypassed admission interceptors")
}

// admitRequest runs the post-authentication checks and hands the request to
// the fair scheduler. It blocks until the sink finishes so backpressure and
// storage-quota errors are reported to the exporter, which retries on 429.
func (r *Receiver) admitRequest(ctx context.Context, id *security.Identity, req *otlpgrpc.ExportLogsServiceRequest, wireBytes int, transport string) (*otlpgrpc.ExportLogsServiceResponse, error) {
	nLogs, seriesKeys := inspectRequest(req)
	if id.Method == security.MethodUnixSocket {
		transport = "unix"
	}
	if err := r.limiter.CheckRequest(id, wireBytes, nLogs, seriesKeys, transport); err != nil {
		return nil, mapQuotaError(err)
	}
	job, err := r.scheduler.Submit(id, req, transport)
	if err != nil {
		return nil, mapQuotaError(err)
	}
	select {
	case err := <-job.Done():
		if err != nil {
			return nil, mapQuotaError(err)
		}
		return &otlpgrpc.ExportLogsServiceResponse{}, nil
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	}
}

func (r *Receiver) grpcQuotaInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	id, ok := security.IdentityFromContext(ctx)
	if !ok {
		// The auth interceptor always sets an identity; fail closed.
		return nil, status.Error(codes.Unauthenticated, security.ReasonUnauthenticated)
	}
	exportReq, ok := req.(*otlpgrpc.ExportLogsServiceRequest)
	if !ok {
		return handler(ctx, req)
	}
	return r.admitRequest(ctx, id, exportReq, proto.Size(exportReq), "grpc")
}

// handleHTTPLogs handles HTTP OTLP log requests.
func (r *Receiver) handleHTTPLogs(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, ok := security.IdentityFromContext(req.Context())
	if !ok {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	q := r.cfg.QuotaFor(id.Tenant)
	// Cap the body at the tenant's per-message allowance BEFORE reading so
	// an oversized POST can never buffer unbounded memory.
	req.Body = http.MaxBytesReader(w, req.Body, int64(q.MaxMessageBytes))
	body, err := io.ReadAll(req.Body)
	if err != nil {
		r.rejects.Record(security.Reject{
			Tenant: id.Tenant, Source: id.Source, Method: id.Method,
			Transport: transportOf(id), Reason: security.ReasonMessageSize,
			Detail: fmt.Sprintf("body exceeds tenant limit %d bytes: %v", q.MaxMessageBytes, err),
		})
		w.Header().Set("Retry-After", "1")
		http.Error(w, `{"error":"message_size"}`, http.StatusRequestEntityTooLarge)
		return
	}

	var exportReq otlpgrpc.ExportLogsServiceRequest
	contentType := req.Header.Get("Content-Type")
	switch {
	case contentType == "application/x-protobuf" || contentType == "application/protobuf":
		if err := proto.Unmarshal(body, &exportReq); err != nil {
			http.Error(w, `{"error":"decode"}`, http.StatusBadRequest)
			return
		}
	case contentType == "application/json":
		if err := r.jsonUnmarshaler.Unmarshal(body, &exportReq); err != nil {
			http.Error(w, `{"error":"decode"}`, http.StatusBadRequest)
			return
		}
	default:
		if err := proto.Unmarshal(body, &exportReq); err != nil {
			if err := r.jsonUnmarshaler.Unmarshal(body, &exportReq); err != nil {
				http.Error(w, `{"error":"decode"}`, http.StatusBadRequest)
				return
			}
		}
	}

	resp, err := r.admitRequest(req.Context(), id, &exportReq, len(body), "http")
	if err != nil {
		writeHTTPError(w, err)
		return
	}

	accept := req.Header.Get("Accept")
	if accept == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		jsonBytes, _ := r.jsonMarshaler.Marshal(resp)
		_, _ = w.Write(jsonBytes)
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	protoBytes, _ := proto.Marshal(resp)
	_, _ = w.Write(protoBytes)
}

func transportOf(id *security.Identity) string {
	if id.Method == security.MethodUnixSocket {
		return "unix"
	}
	return "http"
}

// mapQuotaError converts security quota/sink errors to gRPC status codes.
func mapQuotaError(err error) error {
	var qErr *security.QuotaError
	if errors.As(err, &qErr) {
		switch qErr.Reason {
		case security.ReasonUnauthenticated:
			return status.Error(codes.Unauthenticated, qErr.Error())
		case security.ReasonUnauthorized:
			return status.Error(codes.PermissionDenied, qErr.Error())
		default:
			return status.Error(codes.ResourceExhausted, qErr.Error())
		}
	}
	return status.Error(codes.Internal, err.Error())
}

func writeHTTPError(w http.ResponseWriter, err error) {
	st, ok := status.FromError(err)
	if !ok {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	code := http.StatusInternalServerError
	switch st.Code() {
	case codes.Unauthenticated:
		code = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", `Bearer realm="gonzo-otlp"`)
	case codes.PermissionDenied:
		code = http.StatusForbidden
	case codes.ResourceExhausted:
		code = http.StatusTooManyRequests
		w.Header().Set("Retry-After", "1")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"error":%q,"detail":%q}`, st.Code().String(), st.Message())
}

// inspectRequest counts log records and derives per-resource series keys.
func inspectRequest(req *otlpgrpc.ExportLogsServiceRequest) (int, []string) {
	nLogs := 0
	keys := make([]string, 0)
	seen := make(map[string]bool)
	for _, resourceLogs := range req.ResourceLogs {
		resourceAttrs := make(map[string]string)
		if resourceLogs.Resource != nil {
			for _, attr := range resourceLogs.Resource.Attributes {
				if attr.Key != "" && attr.Value != nil {
					resourceAttrs[attr.Key] = anyValueToString(attr.Value)
				}
			}
		}
		if key := security.SeriesKey(resourceAttrs); key != "" && !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
		for _, scopeLogs := range resourceLogs.ScopeLogs {
			nLogs += len(scopeLogs.LogRecords)
		}
	}
	return nLogs, keys
}

func anyValueToString(v *commonpb.AnyValue) string {
	if v == nil {
		return ""
	}
	switch val := v.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		return val.StringValue
	case *commonpb.AnyValue_BoolValue:
		return fmt.Sprintf("%t", val.BoolValue)
	case *commonpb.AnyValue_IntValue:
		return fmt.Sprintf("%d", val.IntValue)
	case *commonpb.AnyValue_DoubleValue:
		return fmt.Sprintf("%g", val.DoubleValue)
	default:
		return ""
	}
}

// Keep the logspb import tied for future record-level checks.
var _ = logspb.SeverityNumber_SEVERITY_NUMBER_UNSPECIFIED
