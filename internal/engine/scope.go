package engine

import (
	"context"
	"errors"

	"github.com/control-theory/gonzo/internal/security"
)

// LocalTenant is the reserved tenant for trusted local inputs (stdin,
// files, Kubernetes, Victoria Logs) and Unix-socket exporters.
const LocalTenant = security.LocalTenant

// ErrTenantScopeRequired is returned when a read is attempted without an
// authenticated tenant scope. It maps to HTTP 401 at the web layer.
var ErrTenantScopeRequired = errors.New("tenant scope required")

// Scope is the resolved authorization scope for one request. Every engine
// read path requires one: non-admin scopes are pinned to their own tenant,
// admin scopes must still name the tenant they target (no read path ever
// returns data from multiple tenants mixed together).
type Scope struct {
	Tenant string
	Admin  bool
}

type scopeContextKey struct{}

// ContextWithScope stores the scope on ctx.
func ContextWithScope(ctx context.Context, s Scope) context.Context {
	return context.WithValue(ctx, scopeContextKey{}, &s)
}

// ScopeFromContext retrieves the scope stored by the authentication layer.
func ScopeFromContext(ctx context.Context) (Scope, bool) {
	s, ok := ctx.Value(scopeContextKey{}).(*Scope)
	if !ok {
		return Scope{}, false
	}
	return *s, true
}

// resolveTenant enforces that a tenant-scoped read is possible. requested
// is honored only for admin scopes (it comes from an explicit tenant
// selector); non-admin attempts to read another tenant are collapsed to
// the scope's own tenant.
func resolveTenant(ctx context.Context, requested string) (string, error) {
	scope, ok := ScopeFromContext(ctx)
	if !ok || scope.Tenant == "" {
		return "", ErrTenantScopeRequired
	}
	if requested != "" && scope.Admin && requested != scope.Tenant {
		return requested, nil
	}
	return scope.Tenant, nil
}
