package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/control-theory/gonzo/internal/engine"
	"github.com/control-theory/gonzo/internal/security"
	"github.com/control-theory/gonzo/internal/tui"
)

func newTestWeb(t *testing.T, auth *security.Authenticator, rejects *security.RejectLogger, seedTenants ...string) (*httptest.Server, *engine.Engine) {
	t.Helper()
	eng := engine.NewEngine(1000, nil, nil, false)
	for _, tenant := range seedTenants {
		if err := eng.Ingest(tui.LogEntry{
			Tenant: tenant, Message: "log of " + tenant, RawLine: "log of " + tenant,
		}); err != nil {
			t.Fatal(err)
		}
	}
	srv := NewServer(eng, nil, "test", nil, auth, rejects)
	ts := httptest.NewServer(srv.buildHandler(context.Background()))
	t.Cleanup(ts.Close)
	return ts, eng
}

func get(t *testing.T, ts *httptest.Server, path string, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestLocalConsoleLoopbackIsAdmin(t *testing.T) {
	ts, _ := newTestWeb(t, nil, security.NewRejectLogger(8, nil, false), engine.LocalTenant)
	if code, _ := get(t, ts, "/api/status", ""); code != http.StatusOK {
		t.Fatalf("local status code = %d, want 200", code)
	}
	if code, _ := get(t, ts, "/api/tenants", ""); code != http.StatusOK {
		t.Fatalf("local console must have admin endpoints, got %d", code)
	}
}

func TestSecuredDashboardEnforcesTenantScope(t *testing.T) {
	cfg := &security.Config{}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	cfg.APITokens = []security.APITokenConfig{
		{Name: "user", Token: "user-token", Tenant: "team-a"},
		{Name: "admin", Token: "admin-token", Tenant: "ops", Admin: true},
	}
	rejects := security.NewRejectLogger(8, nil, false)
	auth, err := security.NewAuthenticator(cfg, rejects)
	if err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestWeb(t, auth, rejects, "team-a", "team-b")

	// Loopback trust is gone once tokens are configured.
	if code, _ := get(t, ts, "/api/status", ""); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated code = %d, want 401", code)
	}

	// Non-admin user: scoped to own tenant only.
	code, body := get(t, ts, "/api/status", "user-token")
	if code != http.StatusOK {
		t.Fatalf("user status code = %d", code)
	}
	if !strings.Contains(body, "team-a") || strings.Contains(body, "team-b") {
		t.Fatalf("user status leaked tenant data: %s", body)
	}
	if code, _ := get(t, ts, "/api/tenants", "user-token"); code != http.StatusForbidden {
		t.Fatalf("user /api/tenants code = %d, want 403", code)
	}
	if code, _ := get(t, ts, "/api/security/rejections", "user-token"); code != http.StatusForbidden {
		t.Fatalf("user rejections code = %d, want 403", code)
	}

	// Admin gets the tenant inventory and the rejection ledger.
	if code, body := get(t, ts, "/api/tenants", "admin-token"); code != http.StatusOK {
		t.Fatalf("admin /api/tenants code = %d", code)
	} else if !strings.Contains(body, "team-a") || !strings.Contains(body, "team-b") {
		t.Fatalf("admin tenant list missing tenants: %s", body)
	}
	if code, _ := get(t, ts, "/api/security/rejections", "admin-token"); code != http.StatusOK {
		t.Fatalf("admin rejections code = %d", code)
	}
}
