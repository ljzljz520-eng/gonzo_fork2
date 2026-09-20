package otlpreceiver

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	otlpgrpc "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/control-theory/gonzo/internal/security"
)

// captureSink records the authenticated identity behind each accepted
// export.
type captureSink struct {
	mu         sync.Mutex
	identities []*security.Identity
	payloads   int
}

func (s *captureSink) IngestLogs(_ context.Context, id *security.Identity, _ interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities = append(s.identities, id)
	s.payloads++
	return nil
}

func (s *captureSink) tenants() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.identities))
	for i, id := range s.identities {
		out[i] = id.Tenant
	}
	return out
}

func (s *captureSink) methods() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.identities))
	for i, id := range s.identities {
		out[i] = id.Method
	}
	return out
}

func protoExportRequest(service string) *otlpgrpc.ExportLogsServiceRequest {
	return &otlpgrpc.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: &resourcepb.Resource{
				Attributes: []*commonpb.KeyValue{{
					Key:   "service.name",
					Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: service}},
				}},
			},
			ScopeLogs: []*logspb.ScopeLogs{{
				LogRecords: []*logspb.LogRecord{{
					Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "hello from test"}},
				}},
			}},
		}},
	}
}

func jsonExportBody(t *testing.T, service string) []byte {
	t.Helper()
	body, err := protojson.Marshal(protoExportRequest(service))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func startTestReceiver(t *testing.T, cfg *security.Config) (*Receiver, *captureSink, *security.RejectLogger) {
	t.Helper()
	sink := &captureSink{}
	rejects := security.NewRejectLogger(64, nil, cfg.ObserveOnly)
	r, err := New(cfg, sink, rejects)
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("start receiver: %v", err)
	}
	t.Cleanup(r.Stop)
	return r, sink, rejects
}

func httpAddr(t *testing.T, r *Receiver) string {
	t.Helper()
	// Listeners are appended gRPC-first, HTTP-second, UDS-last.
	if len(r.listeners) < 2 {
		t.Fatal("expected gRPC and HTTP TCP listeners")
	}
	return r.listeners[1].Addr().String()
}

func postJSON(t *testing.T, base string, body []byte, headers map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/v1/logs", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestHTTPLoopbackLocalMode(t *testing.T) {
	cfg := &security.Config{GRPCAddr: "127.0.0.1:0", HTTPAddr: "127.0.0.1:0"}
	r, sink, _ := startTestReceiver(t, cfg)

	code := postJSON(t, "http://"+httpAddr(t, r), jsonExportBody(t, "svc"), nil)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if tenants := sink.tenants(); len(tenants) != 1 || tenants[0] != security.LocalTenant {
		t.Fatalf("sink tenants = %v, want [local]", tenants)
	}
	if methods := sink.methods(); methods[0] != security.MethodLoopback {
		t.Fatalf("auth method = %v, want loopback", methods)
	}
}

func TestHTTPAPITokenEnforced(t *testing.T) {
	cfg := &security.Config{
		GRPCAddr:  "127.0.0.1:0",
		HTTPAddr:  "127.0.0.1:0",
		APITokens: []security.APITokenConfig{{Name: "c1", Token: "good-token", Tenant: "team-a"}},
	}
	r, sink, _ := startTestReceiver(t, cfg)
	base := "http://" + httpAddr(t, r)
	body := jsonExportBody(t, "svc")

	if code := postJSON(t, base, body, nil); code != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", code)
	}
	if code := postJSON(t, base, body, map[string]string{"Authorization": "Bearer bad-token"}); code != http.StatusUnauthorized {
		t.Fatalf("bad token: status = %d, want 401", code)
	}
	if code := postJSON(t, base, body, map[string]string{"X-API-Key": "good-token"}); code != http.StatusOK {
		t.Fatalf("valid token: status = %d, want 200", code)
	}
	if tenants := sink.tenants(); len(tenants) != 1 || tenants[0] != "team-a" {
		t.Fatalf("sink tenants = %v, want [team-a]", tenants)
	}
}

func TestHTTPMessageSizeRejected(t *testing.T) {
	cfg := &security.Config{
		GRPCAddr: "127.0.0.1:0",
		HTTPAddr: "127.0.0.1:0",
		Quota:    security.QuotaConfig{MaxMessageBytes: 64},
	}
	r, _, rejects := startTestReceiver(t, cfg)
	body := jsonExportBody(t, "this-service-name-is-very-long-and-pushes-the-body-past-sixty-four-bytes")
	if len(body) <= 64 {
		t.Fatalf("test body only %d bytes", len(body))
	}
	code := postJSON(t, "http://"+httpAddr(t, r), body, nil)
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", code)
	}
	if got := rejects.Snapshot(0).ByReason[security.ReasonMessageSize]; got == 0 {
		t.Fatal("message_size rejection not recorded")
	}
}

func TestRefusesInsecureNonLoopback(t *testing.T) {
	sink := &captureSink{}
	rejects := security.NewRejectLogger(8, nil, false)
	cfg := &security.Config{GRPCAddr: "0.0.0.0:0", HTTPAddr: "127.0.0.1:0"}
	r, err := New(cfg, sink, rejects)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err == nil {
		r.Stop()
		t.Fatal("receiver started on 0.0.0.0 without authentication")
	}
}

func TestUnixSocketHTTPAndGRPCEndToEnd(t *testing.T) {
	// macOS limits sun_path to 104 bytes; t.TempDir() paths are too long.
	sock := filepath.Join(os.TempDir(), fmt.Sprintf("gonzo-otlp-%d.sock", time.Now().UnixNano()))
	_ = os.Remove(sock)
	t.Cleanup(func() { _ = os.Remove(sock) })
	cfg := &security.Config{
		GRPCAddr:   "127.0.0.1:0",
		HTTPAddr:   "127.0.0.1:0",
		UnixSocket: sock,
	}
	_, sink, _ := startTestReceiver(t, cfg)
	body := jsonExportBody(t, "svc-uds")

	// HTTP/1.1 OTLP/JSON over the Unix socket: peer identity comes from
	// the kernel, not any header.
	httpClient := &http.Client{Transport: &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", sock)
		},
	}}
	req, _ := http.NewRequest(http.MethodPost, "http://gonzo.local/v1/logs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("unix http: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unix http status = %d", resp.StatusCode)
	}

	// h2c gRPC over the same multiplexed socket.
	conn, err := grpc.NewClient("passthrough:///gonzo-ux",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return net.Dial("unix", sock)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := otlpgrpc.NewLogsServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := client.Export(ctx, protoExportRequest("svc-uds")); err != nil {
		t.Fatalf("h2c gRPC over unix socket: %v", err)
	}

	if methods := sink.methods(); len(methods) != 2 ||
		methods[0] != security.MethodUnixSocket || methods[1] != security.MethodUnixSocket {
		t.Fatalf("unix methods = %v, want two unix-socket identities", methods)
	}
	if tenants := sink.tenants(); tenants[0] != security.LocalTenant || tenants[1] != security.LocalTenant {
		t.Fatalf("unix tenants = %v", tenants)
	}
}
