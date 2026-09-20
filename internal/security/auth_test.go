package security

import (
	"context"
	"strings"
	"testing"
)

func TestNormalizeDefaults(t *testing.T) {
	c := &Config{}
	if err := c.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if c.GRPCAddr != DefaultGRPCAddr || c.HTTPAddr != DefaultHTTPAddr {
		t.Fatalf("default bind must be loopback, got %q %q", c.GRPCAddr, c.HTTPAddr)
	}
	if c.UnixSocketMode != 0o660 {
		t.Fatalf("socket mode = %o, want 0660", c.UnixSocketMode)
	}
	if c.Quota.MaxMessageBytes <= 0 || c.Quota.QueueDepth <= 0 {
		t.Fatal("quota defaults not filled")
	}
}

func TestNormalizeRejectsBadTokensAndTLS(t *testing.T) {
	if err := (&Config{APITokens: []APITokenConfig{{Name: "x"}}}).Normalize(); err == nil {
		t.Fatal("token without tenant must be rejected")
	}
	tlsRequire := true
	if err := (&Config{TLS: &TLSConfig{CertFile: "a", KeyFile: "b", RequireClient: &tlsRequire}}).Normalize(); err == nil {
		t.Fatal("mTLS without client CA must be rejected")
	}
}

func newAuthenticator(t *testing.T, c *Config) (*Authenticator, *RejectLogger) {
	t.Helper()
	if err := c.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	r := NewRejectLogger(64, nil, false)
	a, err := NewAuthenticator(c, r)
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	return a, r
}

func TestAPITokenAuth(t *testing.T) {
	c := &Config{
		APITokens: []APITokenConfig{{
			Name:       "collector-a",
			Token:      "secret-token",
			Tenant:     "team-a",
			Attributes: map[string]string{"service.name": "trusted-svc"},
		}},
	}
	a, _ := newAuthenticator(t, c)
	ctx := context.Background()

	id, fail := a.Authenticate(ctx, nil, false, nil, "secret-token")
	if fail != nil {
		t.Fatalf("valid token rejected: %v", fail)
	}
	if id.Tenant != "team-a" || id.Method != MethodAPIToken || id.Attributes["service.name"] != "trusted-svc" {
		t.Fatalf("unexpected identity: %+v", id)
	}

	if _, fail = a.Authenticate(ctx, nil, false, nil, "wrong"); fail == nil || fail.reason != ReasonUnauthenticated {
		t.Fatalf("bad token must fail unauthenticated, got %+v", fail)
	}
}

func TestJWTShapedBearerNeverFallsBackWhenOIDCConfigured(t *testing.T) {
	c := &Config{
		OIDC:      &OIDCConfig{IssuerURL: "https://issuer.example", Audiences: []string{"gonzo"}},
		APITokens: []APITokenConfig{{Name: "t", Token: "plain-token", Tenant: "team-a"}},
	}
	a, _ := newAuthenticator(t, c)
	// A syntactically JWT-shaped bearer that fails validation must be
	// rejected outright even though a valid static API token also exists.
	if _, fail := a.Authenticate(context.Background(), nil, false, nil, "aaa.bbb.ccc"); fail == nil {
		t.Fatal("invalid JWT-shaped bearer must not authenticate")
	}
}

func TestLoopbackImplicitLocalIdentity(t *testing.T) {
	// No network auth configured: loopback peers are machine-local.
	a, _ := newAuthenticator(t, &Config{})
	id, fail := a.Authenticate(context.Background(), nil, true, nil, "")
	if fail != nil {
		t.Fatalf("loopback peer denied in local mode: %v", fail)
	}
	if id.Tenant != LocalTenant || id.Method != MethodLoopback {
		t.Fatalf("loopback identity = %+v", id)
	}

	// Same local config, non-loopback peer with no credentials: fail closed.
	if _, fail = a.Authenticate(context.Background(), nil, false, nil, ""); fail == nil {
		t.Fatal("remote peer without credentials must be rejected")
	}
}

func TestLoopbackTrustRemovedOnceTokensConfigured(t *testing.T) {
	c := &Config{APITokens: []APITokenConfig{{Name: "t", Token: "s", Tenant: "team-a"}}}
	a, _ := newAuthenticator(t, c)
	if _, fail := a.Authenticate(context.Background(), nil, true, nil, ""); fail == nil {
		t.Fatal("loopback without a token must be rejected once auth is configured")
	}
}

func TestUnixSocketPeerAlwaysWins(t *testing.T) {
	c := &Config{APITokens: []APITokenConfig{{Name: "t", Token: "s", Tenant: "team-a"}}}
	a, _ := newAuthenticator(t, c)
	peer := &LocalPeer{Socket: "/tmp/gonzo.sock", UID: 1000, GID: 1000}
	id, fail := a.Authenticate(context.Background(), peer, false, nil, "s")
	if fail != nil {
		t.Fatalf("unix peer denied: %v", fail)
	}
	if id.Tenant != LocalTenant || id.Method != MethodUnixSocket {
		t.Fatalf("kernel peer must map to local tenant, got %+v", id)
	}
	if !strings.HasPrefix(id.Source, "unix:uid=1000") {
		t.Fatalf("source = %q", id.Source)
	}
}

func TestStampIdentityStripsForgery(t *testing.T) {
	id := &Identity{
		Tenant:     "team-a",
		Source:     "spiffe://example.org/ns/prod/sa/collector",
		Method:     MethodMTLSSPIFFE,
		Attributes: map[string]string{"service.name": "trusted-svc"},
	}
	attrs := map[string]string{
		"gonzo.tenant":              "team-b",   // exact reserved key: overwritten
		"gonzo.source":              "attacker", // exact reserved key: overwritten
		"gonzo.auth_method":         "forged",   // exact reserved key: overwritten
		"gonzo.backdoor":            "x",        // reserved namespace: dropped
		"GoNzO.escalated.privilege": "x",        // case-mixed reserved namespace: dropped
		"service.name":              "forged-svc",
		"deployment.environment":    "prod",
	}
	StampIdentity(id, attrs)

	if attrs[AttrTenant] != "team-a" {
		t.Fatalf("gonzo.tenant = %q", attrs[AttrTenant])
	}
	if attrs[AttrSource] != id.Source || attrs[AttrMethod] != MethodMTLSSPIFFE {
		t.Fatalf("authoritative keys not stamped: %v", attrs)
	}
	if _, ok := attrs["gonzo.backdoor"]; ok {
		t.Fatal("client-supplied gonzo.backdoor survived stamping")
	}
	if _, ok := attrs["GoNzO.escalated.privilege"]; ok {
		t.Fatal("case-mixed gonzo.* key survived stamping")
	}
	if attrs["service.name"] != "trusted-svc" {
		t.Fatalf("untrusted service.name not overwritten: %q", attrs["service.name"])
	}
	if attrs["deployment.environment"] != "prod" {
		t.Fatal("ordinary attribute must be preserved")
	}
}
