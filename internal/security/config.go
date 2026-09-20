package security

import (
	"errors"
	"fmt"
	"os"
)

// Default addresses and reserved tenant names.
const (
	DefaultGRPCAddr = "127.0.0.1:4317"
	DefaultHTTPAddr = "127.0.0.1:4318"

	// LocalTenant is the tenant assigned to trusted local inputs (stdin,
	// files, Kubernetes, Victoria Logs) and to Unix socket exporters.
	LocalTenant = "local"

	// ObserveTenant is used for unauthenticated traffic when ObserveOnly is
	// enabled. It never appears when the receiver runs in enforce mode.
	ObserveTenant = "observe-unauthenticated"
)

// Config configures authentication, transport security and per-tenant
// quotas for an OTLP receiver surface.
type Config struct {
	// GRPCAddr/HTTPAddr are TCP listen addresses. They default to loopback
	// explicitly: binding every interface requires an opt-in address.
	GRPCAddr string `mapstructure:"grpc-addr" yaml:"grpc-addr,omitempty"`
	HTTPAddr string `mapstructure:"http-addr" yaml:"http-addr,omitempty"`

	// UnixSocket, when set, additionally (or exclusively) serves OTLP on a
	// local Unix domain socket. The socket is protected by filesystem
	// permissions; connecting peers are authenticated via SO_PEERCRED and
	// mapped to LocalTenant.
	UnixSocket     string      `mapstructure:"unix-socket" yaml:"unix-socket,omitempty"`
	UnixSocketMode os.FileMode `mapstructure:"unix-socket-mode" yaml:"unix-socket-mode,omitempty"`

	// TLS enables mTLS. Required for non-loopback TCP serving.
	TLS *TLSConfig `mapstructure:"tls" yaml:"tls,omitempty"`

	// OIDC validates Bearer JWTs against an OIDC issuer (JWKS fetched and
	// cached from the issuer discovery document).
	OIDC *OIDCConfig `mapstructure:"oidc" yaml:"oidc,omitempty"`

	// APITokens are static shared secrets mapped to a tenant/source.
	APITokens []APITokenConfig `mapstructure:"api-tokens" yaml:"api-tokens,omitempty"`

	// SpiffeTenants optionally pins SPIFFE IDs (or trust domains) to tenant
	// keys. Keys may be full IDs ("spiffe://td/ns/x/sa/y") or trust domains
	// ("spiffe://td"). A full ID wins over a trust-domain entry.
	SpiffeTenants map[string]string `mapstructure:"spiffe-tenants" yaml:"spiffe-tenants,omitempty"`

	// AdminIdentities lists SPIFFE IDs / API token names / OIDC subjects that
	// receive dashboard cross-tenant read access.
	AdminIdentities []string `mapstructure:"admin-identities" yaml:"admin-identities,omitempty"`

	// DefaultTenant is assigned to credentials that do not encode a tenant
	// (e.g. OIDC tokens without a tenant claim). Empty means "reject".
	DefaultTenant string `mapstructure:"default-tenant" yaml:"default-tenant,omitempty"`

	// ObserveOnly runs authentication in shadow mode: failures are recorded
	// as rejections but traffic is admitted under ObserveTenant. This is a
	// rollout/debugging switch only — enforce (false) is the secure default.
	ObserveOnly bool `mapstructure:"observe-only" yaml:"observe-only,omitempty"`

	// Quota holds per-tenant limits applied before every accepted export.
	Quota QuotaConfig `mapstructure:"quota" yaml:"quota,omitempty"`

	// TenantOverrides applies custom quota limits to specific tenants.
	TenantOverrides map[string]QuotaConfig `mapstructure:"tenant-overrides" yaml:"tenant-overrides,omitempty"`
}

// TLSConfig configures server-side mTLS.
type TLSConfig struct {
	CertFile string `mapstructure:"cert-file" yaml:"cert-file"`
	KeyFile  string `mapstructure:"key-file" yaml:"key-file"`
	CAFile   string `mapstructure:"client-ca-file" yaml:"client-ca-file"`
	// TrustDomains restricts acceptable client SPIFFE trust domains. Empty
	// allows any verified client certificate (still requires a SPIFFE URI).
	TrustDomains []string `mapstructure:"spiffe-trust-domains" yaml:"spiffe-trust-domains,omitempty"`
	// RequireClient makes client certificates mandatory. Defaults to true
	// whenever TLS is configured; set false to allow anonymous TLS (not
	// recommended — another auth method must then be present).
	RequireClient *bool `mapstructure:"require-client-cert" yaml:"require-client-cert,omitempty"`
}

// OIDCConfig configures OIDC Bearer token validation.
type OIDCConfig struct {
	IssuerURL   string   `mapstructure:"issuer-url" yaml:"issuer-url"`
	JWKSURL     string   `mapstructure:"jwks-url" yaml:"jwks-url,omitempty"`
	Audiences   []string `mapstructure:"audiences" yaml:"audiences"`
	TenantClaim string   `mapstructure:"tenant-claim" yaml:"tenant-claim,omitempty"`
	// AttributeClaims maps OIDC claim names to OTLP attribute keys; claim
	// string values overwrite untrusted resource attributes.
	AttributeClaims map[string]string `mapstructure:"attribute-claims" yaml:"attribute-claims,omitempty"`
	// HMACSecrets enables HS256 verification (dev/test only).
	HMACSecrets []string `mapstructure:"hmac-secrets" yaml:"hmac-secrets,omitempty"`
}

// APITokenConfig maps a static token to a tenant identity.
type APITokenConfig struct {
	// Name identifies the token in logs (never put the secret here).
	Name string `mapstructure:"name" yaml:"name"`
	// Token is the bearer secret. Prefer providing it via the
	// GONZO_OTLP_API_TOKEN_<NAME> environment variable or a 0600 config file;
	// an explicit Token here still works.
	Token string `mapstructure:"token" yaml:"token,omitempty"`
	// TokenEnv names an environment variable holding the secret.
	TokenEnv string `mapstructure:"token-env" yaml:"token-env,omitempty"`
	Tenant   string `mapstructure:"tenant" yaml:"tenant"`
	// Attributes stamped onto exports made with this token.
	Attributes map[string]string `mapstructure:"attributes" yaml:"attributes,omitempty"`
	Admin      bool              `mapstructure:"admin" yaml:"admin,omitempty"`
}

// QuotaConfig is the per-tenant resource budget. Zero values fall back to
// defaults from DefaultQuota.
type QuotaConfig struct {
	// MaxMessageBytes caps a single export request (wire size).
	MaxMessageBytes int `mapstructure:"max-message-bytes" yaml:"max-message-bytes,omitempty"`
	// RequestsPerSecond/Burst cap export RPC frequency.
	RequestsPerSecond float64 `mapstructure:"requests-per-second" yaml:"requests-per-second,omitempty"`
	RequestBurst      int     `mapstructure:"request-burst" yaml:"request-burst,omitempty"`
	// LogsPerSecond/Burst cap accepted log records.
	LogsPerSecond float64 `mapstructure:"logs-per-second" yaml:"logs-per-second,omitempty"`
	LogBurst      int     `mapstructure:"log-burst" yaml:"log-burst,omitempty"`
	// MaxSeries caps the number of distinct series (fingerprints derived
	// from stable resource attributes) a tenant may create.
	MaxSeries int `mapstructure:"max-series" yaml:"max-series,omitempty"`
	// SeriesTTL evicts idle series so long-lived tenants recycle cardinality.
	SeriesTTL string `mapstructure:"series-ttl" yaml:"series-ttl,omitempty"`
	// QueueDepth is the bounded per-tenant parse queue. When full, new
	// exports for that tenant get ResourceExhausted immediately — other
	// tenants keep draining independently.
	QueueDepth int `mapstructure:"queue-depth" yaml:"queue-depth,omitempty"`
	// MaxBufferEntries caps retained logs per tenant (ring buffer).
	MaxBufferEntries int `mapstructure:"max-buffer-entries" yaml:"max-buffer-entries,omitempty"`
	// MaxBufferBytes caps the in-memory size of a tenant's ring buffer.
	MaxBufferBytes int64 `mapstructure:"max-buffer-bytes" yaml:"max-buffer-bytes,omitempty"`
}

// DefaultQuota returns the built-in per-tenant limits.
func DefaultQuota() QuotaConfig {
	return QuotaConfig{
		MaxMessageBytes:   4 * 1024 * 1024,
		RequestsPerSecond: 50,
		RequestBurst:      100,
		LogsPerSecond:     20000,
		LogBurst:          40000,
		MaxSeries:         2000,
		SeriesTTL:         "30m",
		QueueDepth:        256,
		MaxBufferEntries:  5000,
		MaxBufferBytes:    64 * 1024 * 1024,
	}
}

// HardMaxMessageBytes is the protocol-level ceiling regardless of per-tenant
// configuration, so gRPC/HTTP framing never buffers unbounded payloads.
const HardMaxMessageBytes = 16 * 1024 * 1024

// Normalize fills defaults and validates the configuration.
func (c *Config) Normalize() error {
	if c == nil {
		return errors.New("nil security config")
	}
	if c.GRPCAddr == "" {
		c.GRPCAddr = DefaultGRPCAddr
	}
	if c.HTTPAddr == "" {
		c.HTTPAddr = DefaultHTTPAddr
	}
	if c.UnixSocketMode == 0 {
		c.UnixSocketMode = 0o660
	}

	d := DefaultQuota()
	c.Quota = mergeQuota(d, c.Quota)
	for tenant, q := range c.TenantOverrides {
		c.TenantOverrides[tenant] = mergeQuota(c.Quota, q)
	}

	for i := range c.APITokens {
		t := &c.APITokens[i]
		if t.Token == "" && t.TokenEnv != "" {
			t.Token = os.Getenv(t.TokenEnv)
		}
		if t.Name == "" {
			return fmt.Errorf("api-tokens[%d]: name is required", i)
		}
		if t.Tenant == "" {
			return fmt.Errorf("api-tokens[%d]: tenant is required", i)
		}
		if t.Token == "" {
			return fmt.Errorf("api-tokens[%d] %q: empty token (set token or token-env)", i, t.Name)
		}
	}

	if c.TLS != nil {
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return errors.New("tls: cert-file and key-file are required")
		}
		require := true
		if c.TLS.RequireClient != nil {
			require = *c.TLS.RequireClient
		}
		c.TLS.RequireClient = &require
		if require && c.TLS.CAFile == "" {
			return errors.New("tls: client-ca-file is required when require-client-cert is true")
		}
	}

	if c.OIDC != nil {
		if c.OIDC.IssuerURL == "" {
			return errors.New("oidc: issuer-url is required")
		}
		if len(c.OIDC.Audiences) == 0 {
			return errors.New("oidc: at least one audience is required")
		}
		if c.OIDC.TenantClaim == "" {
			c.OIDC.TenantClaim = "tenant"
		}
	}

	return nil
}

// QuotaFor returns the effective quota for a tenant (override or default).
func (c *Config) QuotaFor(tenant string) QuotaConfig {
	if q, ok := c.TenantOverrides[tenant]; ok {
		return q
	}
	return c.Quota
}

// mergeQuota applies Defaults for zero-valued fields in q.
func mergeQuota(base, q QuotaConfig) QuotaConfig {
	if q.MaxMessageBytes == 0 {
		q.MaxMessageBytes = base.MaxMessageBytes
	}
	if q.RequestsPerSecond == 0 {
		q.RequestsPerSecond = base.RequestsPerSecond
	}
	if q.RequestBurst == 0 {
		q.RequestBurst = base.RequestBurst
	}
	if q.LogsPerSecond == 0 {
		q.LogsPerSecond = base.LogsPerSecond
	}
	if q.LogBurst == 0 {
		q.LogBurst = base.LogBurst
	}
	if q.MaxSeries == 0 {
		q.MaxSeries = base.MaxSeries
	}
	if q.SeriesTTL == "" {
		q.SeriesTTL = base.SeriesTTL
	}
	if q.QueueDepth == 0 {
		q.QueueDepth = base.QueueDepth
	}
	if q.MaxBufferEntries == 0 {
		q.MaxBufferEntries = base.MaxBufferEntries
	}
	if q.MaxBufferBytes == 0 {
		q.MaxBufferBytes = base.MaxBufferBytes
	}
	if q.MaxMessageBytes > HardMaxMessageBytes {
		q.MaxMessageBytes = HardMaxMessageBytes
	}
	return q
}
