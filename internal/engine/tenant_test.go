package engine

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/control-theory/gonzo/internal/tui"
)

type stubQuotaProvider func(tenant string) (int, int64)

func (f stubQuotaProvider) LimitsFor(tenant string) (int, int64) { return f(tenant) }

func ingestN(t *testing.T, e *Engine, tenant string, n int) {
	t.Helper()
	for i := range n {
		err := e.Ingest(tui.LogEntry{
			Tenant:   tenant,
			Message:  "hello world",
			RawLine:  "hello world",
			Severity: "info",
		})
		if err != nil {
			t.Fatalf("ingest %s/%d: %v", tenant, i, err)
		}
	}
}

func scopeCtx(tenant string, admin bool) context.Context {
	return ContextWithScope(context.Background(), Scope{Tenant: tenant, Admin: admin})
}

func TestTenantIsolationAndScopeEnforcement(t *testing.T) {
	e := NewEngine(1000, nil, nil, false)
	ingestN(t, e, "team-a", 1)
	ingestN(t, e, "team-b", 2)

	tenants := e.ActiveTenants()
	slices.Sort(tenants)
	if !slices.Equal(tenants, []string{"team-a", "team-b"}) {
		t.Fatalf("active tenants = %v", tenants)
	}

	statsA, err := e.GetStats(scopeCtx("team-a", false))
	if err != nil {
		t.Fatal(err)
	}
	if statsA.Tenant != "team-a" || statsA.TotalLogsEver != 1 {
		t.Fatalf("team-a stats = %+v", statsA)
	}

	statsB, err := e.GetStats(scopeCtx("team-b", false))
	if err != nil {
		t.Fatal(err)
	}
	if statsB.TotalLogsEver != 2 {
		t.Fatalf("team-b stats = %+v", statsB)
	}

	// No scope at all: fail closed.
	if _, err := e.GetStats(context.Background()); !errors.Is(err, ErrTenantScopeRequired) {
		t.Fatalf("unscoped read err = %v, want ErrTenantScopeRequired", err)
	}

	// Non-admin scope can only ever read its own tenant; an explicit
	// request for another tenant collapses back to the scope tenant.
	got, err := resolveTenant(scopeCtx("team-a", false), "team-b")
	if err != nil || got != "team-a" {
		t.Fatalf("non-admin cross-tenant resolution = %q, %v", got, err)
	}
	got, err = resolveTenant(scopeCtx("admin", true), "team-b")
	if err != nil || got != "team-b" {
		t.Fatalf("admin explicit tenant resolution = %q, %v", got, err)
	}
	// Even admins must name exactly one tenant; unscoped admin reads
	// default to the admin's own tenant (no mixed aggregation).
	got, err = resolveTenant(scopeCtx("admin", true), "")
	if err != nil || got != "admin" {
		t.Fatalf("admin unscoped resolution = %q, %v", got, err)
	}

	// Resetting one tenant must not touch the other.
	e.ResetTenant("team-a")
	if _, err := e.GetStats(scopeCtx("team-b", false)); err != nil {
		t.Fatal(err)
	}
	if stats := e.StatsFor("team-b"); stats.TotalLogsEver != 2 {
		t.Fatalf("team-b lost data after team-a reset: %+v", stats)
	}
	if stats := e.StatsFor("team-a"); stats.TotalLogsEver != 0 {
		t.Fatalf("team-a reset did not clear: %+v", stats)
	}
}

func TestPerTenantEntryEviction(t *testing.T) {
	e := NewEngine(1000, nil, nil, false)
	e.SetStorageQuotaProvider(stubQuotaProvider(func(string) (int, int64) {
		return 3, 0 // three retained entries per tenant, unlimited bytes
	}))
	ingestN(t, e, "team-q", 6)
	stats := e.StatsFor("team-q")
	if stats.BufferUsed != 3 {
		t.Fatalf("buffer used = %d, want 3 (ring eviction)", stats.BufferUsed)
	}
	if stats.TotalLogsEver != 6 {
		t.Fatalf("lifetime count = %d, want 6", stats.TotalLogsEver)
	}
	if stats.BufferSize != 3 {
		t.Fatalf("buffer size = %d, want quota 3", stats.BufferSize)
	}
}

func TestOversizedRecordRejected(t *testing.T) {
	e := NewEngine(1000, nil, nil, false)
	e.SetStorageQuotaProvider(stubQuotaProvider(func(string) (int, int64) {
		return 100, 5 // whole tenant byte budget is 5 bytes
	}))
	err := e.Ingest(tui.LogEntry{Tenant: "team-q", Message: "this record is way too big", RawLine: "this record is way too big"})
	if !errors.Is(err, ErrStorageQuota) {
		t.Fatalf("oversized ingest err = %v, want ErrStorageQuota", err)
	}
	if stats := e.StatsFor("team-q"); stats.TotalLogsEver != 0 {
		t.Fatalf("rejected record was counted: %+v", stats)
	}
}

func TestIngestDefaultsEmptyTenantToLocal(t *testing.T) {
	e := NewEngine(1000, nil, nil, false)
	if err := e.Ingest(tui.LogEntry{Message: "x", RawLine: "x"}); err != nil {
		t.Fatal(err)
	}
	stats, err := e.GetStats(scopeCtx(LocalTenant, false))
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalLogsEver != 1 || stats.Tenant != LocalTenant {
		t.Fatalf("local stats = %+v", stats)
	}
}
