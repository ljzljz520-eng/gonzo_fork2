package security

import (
	"context"
	"crypto/x509"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Authenticator resolves transport evidence (Unix socket peer, client
// certificate, Bearer token) to an authoritative Identity.
type Authenticator struct {
	cfg     *Config
	oidc    *oidcVerifier
	tokens  map[string]*APITokenConfig
	rejects *RejectLogger
}

// NewAuthenticator builds the authenticator from normalized config.
func NewAuthenticator(cfg *Config, rejects *RejectLogger) (*Authenticator, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	a := &Authenticator{
		cfg:     cfg,
		tokens:  make(map[string]*APITokenConfig),
		rejects: rejects,
	}
	if cfg.OIDC != nil {
		a.oidc = newOIDCVerifier(cfg.OIDC)
	}
	for i := range cfg.APITokens {
		t := &cfg.APITokens[i]
		a.tokens[t.Token] = t
	}
	return a, nil
}

// failure describes why authentication/authorization failed.
type failure struct {
	reason string
	detail string
}

// Authenticate resolves identity from the supplied evidence. localPeer is
// non-nil for connections accepted on the Unix domain socket. loopbackPeer
// reports a TCP peer on a loopback address. certs are the verified peer
// certificates. bearer is the raw token from Authorization or X-API-Key.
// On failure the returned failure carries a stable Reason*.
func (a *Authenticator) Authenticate(ctx context.Context, localPeer *LocalPeer, loopbackPeer bool, certs []*x509.Certificate, bearer string) (*Identity, *failure) {
	// 1. Kernel-authenticated local peer always wins. A Unix socket is
	//    protected by filesystem permissions; credentials are supplied by
	//    SO_PEERCRED/getpeereid and cannot be forged over the socket.
	if localPeer != nil {
		return &Identity{
			Tenant: LocalTenant,
			Source: localPeer.Source(),
			Method: MethodUnixSocket,
		}, nil
	}

	// 2. When no network authentication method is configured at all, a
	//    loopback TCP peer is a machine-local principal: the listen surface
	//    is validated to be loopback-only at startup, so it can never be
	//    reached off-box. Configuring mTLS/OIDC/tokens removes this trust.
	if loopbackPeer && a.cfg.TLS == nil && a.oidc == nil && len(a.tokens) == 0 {
		return &Identity{
			Tenant: LocalTenant,
			Source: "loopback",
			Method: MethodLoopback,
		}, nil
	}

	// 3. mTLS client certificate (chain already verified by TLS config).
	if len(certs) > 0 {
		if id, err := SpiffeIDFromCert(certs[0]); err == nil {
			tenant := TenantFromSpiffe(a.cfg, id)
			if tenant == "" {
				return nil, &failure{ReasonUnauthorized, "no tenant mapping for spiffe id " + id.String()}
			}
			return &Identity{
				Tenant: tenant,
				Source: id.String(),
				Method: MethodMTLSSPIFFE,
				Admin:  a.isAdmin(id.String()),
			}, nil
		} else if a.cfg.TLS != nil {
			// A cert was presented on an mTLS surface but carries no valid
			// SPIFFE identity: reject rather than silently falling back.
			return nil, &failure{ReasonUnauthenticated, err.Error()}
		}
	}

	// 4. Bearer token (OIDC JWT or static API token).
	if bearer != "" {
		if a.oidc != nil && strings.Count(bearer, ".") == 2 {
			if id, err := a.oidc.verify(ctx, bearer); err == nil {
				if id.Tenant == "" {
					id.Tenant = a.cfg.DefaultTenant
				}
				if id.Tenant == "" {
					return nil, &failure{ReasonUnauthorized, "oidc token has no tenant and no default tenant configured"}
				}
				id.Admin = a.isAdmin(id.Source) || a.isAdmin(oidcSubject(id.Source))
				return id, nil
			} else if _, isAPIToken := a.tokens[bearer]; !isAPIToken {
				// JWT-shaped and invalid: do not fall through.
				return nil, &failure{ReasonUnauthenticated, "oidc token invalid: " + err.Error()}
			}
		}
		if tok, ok := a.tokens[bearer]; ok {
			return &Identity{
				Tenant:     tok.Tenant,
				Source:     "api-token:" + tok.Name,
				Method:     MethodAPIToken,
				Admin:      tok.Admin || a.isAdmin("api-token:"+tok.Name),
				Attributes: cloneAttrs(tok.Attributes),
			}, nil
		}
		return nil, &failure{ReasonUnauthenticated, "bearer token rejected"}
	}

	return nil, &failure{ReasonUnauthenticated, "no client certificate, bearer token or unix socket peer"}
}

func (a *Authenticator) isAdmin(source string) bool {
	for _, id := range a.cfg.AdminIdentities {
		if id == source {
			return true
		}
	}
	return false
}

func oidcSubject(source string) string {
	if i := strings.LastIndex(source, "#"); i >= 0 {
		return source[i+1:]
	}
	return ""
}

func cloneAttrs(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// admit applies observe-only semantics: in observe mode failures are
// recorded but traffic is admitted under the isolated ObserveTenant so it
// can never share statistics or AI context with real tenants.
func (a *Authenticator) admit(transport string, f *failure) (*Identity, bool) {
	a.rejects.Record(Reject{
		Tenant:    ObserveTenant,
		Transport: transport,
		Reason:    f.reason,
		Detail:    f.detail,
	})
	if a.cfg.ObserveOnly {
		return &Identity{
			Tenant: ObserveTenant,
			Source: "observe:" + f.reason,
			Method: "observe-only",
		}, true
	}
	return nil, false
}

// bearerFromHeaders extracts a bearer secret from Authorization or X-API-Key.
func bearerFromHeaders(header http.Header) string {
	if h := header.Get("Authorization"); h != "" {
		if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
			return strings.TrimSpace(h[7:])
		}
	}
	return header.Get("X-API-Key")
}

// HTTPMiddleware authenticates every request and stores the identity in the
// request context. Unauthenticated requests get 401, identity-resolved but
// unmapped/forbidden ones get 403. In observe mode the response remains 200
// but the rejection is recorded and the request runs as ObserveTenant.
func (a *Authenticator) HTTPMiddleware(transport string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		localPeer := UnixPeerFromAddr(r.RemoteAddr)
		loopbackPeer := IsLoopbackTCP(r.RemoteAddr)
		var certs []*x509.Certificate
		if r.TLS != nil {
			certs = r.TLS.PeerCertificates
		}
		id, fail := a.Authenticate(r.Context(), localPeer, loopbackPeer, certs, bearerFromHeaders(r.Header))
		if fail != nil {
			admitted, ok := a.admit(transport, fail)
			if !ok {
				w.Header().Set("WWW-Authenticate", `Bearer realm="gonzo-otlp"`)
				code := http.StatusUnauthorized
				if fail.reason == ReasonUnauthorized {
					code = http.StatusForbidden
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				_, _ = w.Write([]byte(`{"error":"` + fail.reason + `","detail":"` + jsonSafe(fail.detail) + `"}`))
				return
			}
			id = admitted
		}
		ctx := ContextWithIdentity(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GRPCStreamInterceptor rejects unauthenticated streaming RPCs.
func (a *Authenticator) GRPCStreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, err := a.authenticateGRPC(ss.Context())
	if err != nil {
		return err
	}
	return handler(srv, &wrappedServerStream{ServerStream: ss, ctx: ctx})
}

// GRPCUnaryInterceptor rejects unauthenticated unary RPCs and stores the
// identity in the handler context.
func (a *Authenticator) GRPCUnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	ctx, err := a.authenticateGRPC(ctx)
	if err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (a *Authenticator) authenticateGRPC(ctx context.Context) (context.Context, error) {
	var localPeer *LocalPeer
	var loopbackPeer bool
	var certs []*x509.Certificate

	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		localPeer = UnixPeerFromAddr(p.Addr.String())
		loopbackPeer = IsLoopbackTCP(p.Addr.String())
		if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			certs = ti.State.PeerCertificates
		}
	}

	bearer := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("authorization"); len(vals) > 0 {
			bearer = strings.TrimPrefix(vals[0], "Bearer ")
		}
		if bearer == "" {
			if vals := md.Get("x-api-key"); len(vals) > 0 {
				bearer = vals[0]
			}
		}
	}

	id, fail := a.Authenticate(ctx, localPeer, loopbackPeer, certs, strings.TrimSpace(bearer))
	if fail != nil {
		admitted, ok := a.admit("grpc", fail)
		if !ok {
			code := codes.Unauthenticated
			if fail.reason == ReasonUnauthorized {
				code = codes.PermissionDenied
			}
			return nil, status.Error(code, fail.reason+": "+fail.detail)
		}
		id = admitted
	}
	return ContextWithIdentity(ctx, id), nil
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context { return w.ctx }

// jsonSafe escapes the minimum characters needed for a JSON error body.
func jsonSafe(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}
