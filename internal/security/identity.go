// Package security provides transport authentication (mTLS/SPIFFE, OIDC,
// static API tokens, local Unix domain sockets), authoritative workload
// identity mapping, per-tenant quota enforcement and observable rejections
// for the Gonzo OTLP receiver and web dashboard.
package security

import "context"

// Authentication methods.
const (
	MethodMTLSSPIFFE = "mtls-spiffe"
	MethodOIDC       = "oidc"
	MethodAPIToken   = "api-token"
	MethodUnixSocket = "unix-socket"
	MethodLoopback   = "loopback"
)

// Trusted attribute keys stamped onto every accepted record. Exporters can
// never set or override these — any client-supplied values are dropped.
const (
	AttrTenant = "gonzo.tenant"
	AttrSource = "gonzo.source"
	AttrMethod = "gonzo.auth_method"
)

// Identity is the authenticated principal behind an export request or a
// dashboard connection. It is derived exclusively from the transport
// (client certificate, bearer token or Unix socket peer credentials) and
// never from OTLP resource attributes.
type Identity struct {
	// Tenant is the authoritative tenant key all ingested logs are scoped to.
	Tenant string
	// Source is the workload identity (SPIFFE ID, OIDC sub, token name or
	// "unix:uid=…"). Recorded as the trusted gonzo.source attribute.
	Source string
	// Method is one of the Method* constants.
	Method string
	// Admin may read across tenants from the dashboard. It never grants
	// special treatment on the ingest path quotas.
	Admin bool
	// Attributes are trusted claim/token attributes that overwrite
	// attacker-controlled resource attributes (e.g. service.name).
	Attributes map[string]string
}

type identityContextKey struct{}

// ContextWithIdentity returns a context carrying the authenticated identity.
func ContextWithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, id)
}

// IdentityFromContext extracts the identity previously stored with
// ContextWithIdentity. The boolean is false when no identity is present.
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(identityContextKey{}).(*Identity)
	return id, ok
}

// StampAttributes merges trusted identity attributes into an untrusted
// attribute map (OTLP resource + record attributes):
//
//  1. client-supplied gonzo.* identity keys are always dropped;
//  2. trusted identity attributes overwrite any same-named untrusted key;
//  3. gonzo.tenant/gonzo.source/gonzo.auth_method are stamped last, so a
//     forged resource attribute can never impersonate another workload or
//     tenant.
//
// The passed map is mutated in place and also returned for convenience.
func StampIdentity(id *Identity, attrs map[string]string) map[string]string {
	if attrs == nil {
		attrs = make(map[string]string)
	}
	for key := range attrs {
		if isReservedKey(key) {
			delete(attrs, key)
		}
	}
	for key, value := range id.Attributes {
		if isReservedKey(key) {
			continue // reserved keys are controlled solely by the identity itself
		}
		attrs[key] = value
	}
	attrs[AttrTenant] = id.Tenant
	attrs[AttrSource] = id.Source
	attrs[AttrMethod] = id.Method
	return attrs
}

// isReservedKey reports whether key belongs to the trusted gonzo.* namespace.
func isReservedKey(key string) bool {
	// Simple prefix match; compare case-insensitively because OTLP attribute
	// keys are not guaranteed to be normalised by the exporter.
	return len(key) > len(AttrTenant) &&
		(key[0] == 'g' || key[0] == 'G') &&
		equalFold(key[:6], "gonzo.")
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
