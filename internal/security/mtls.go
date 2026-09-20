package security

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// BuildServerTLSConfig creates the server-side TLS config for mTLS:
//   - TLS 1.2+ only;
//   - client certificates verified against the configured CA pool;
//   - the leaf certificate MUST carry a syntactically valid SPIFFE URI SAN
//     whose trust domain is in the allow list (when configured).
func BuildServerTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	if cfg == nil {
		return nil, errors.New("tls config is nil")
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	require := cfg.RequireClient == nil || *cfg.RequireClient
	if require {
		caPEM, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("load client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("client CA file contains no usable certificates")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	}

	allowed := make(map[string]bool, len(cfg.TrustDomains))
	for _, td := range cfg.TrustDomains {
		allowed[strings.ToLower(strings.TrimPrefix(strings.TrimSpace(td), "spiffe://"))] = true
	}

	// Defense in depth: chain verification is handled by ClientCAs/ClientAuth;
	// VerifyConnection enforces the SPIFFE shape and trust-domain allow list
	// on the presented leaf.
	tlsCfg.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			if require {
				return errors.New("no client certificate presented")
			}
			return nil
		}
		id, err := SpiffeIDFromCert(state.PeerCertificates[0])
		if err != nil {
			return err
		}
		if len(allowed) > 0 && !allowed[strings.ToLower(id.TrustDomain)] {
			return fmt.Errorf("spiffe trust domain %q is not allowed", id.TrustDomain)
		}
		return nil
	}

	return tlsCfg, nil
}

// SpiffeID is a parsed SPIFFE identity URI.
type SpiffeID struct {
	TrustDomain string
	Path        string // includes leading "/"
	raw         string
}

// String returns the canonical spiffe:// URI.
func (s SpiffeID) String() string { return s.raw }

// ParseSpiffeID parses and validates "spiffe://trust-domain/path…".
func ParseSpiffeID(raw string) (*SpiffeID, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid spiffe id %q: %w", raw, err)
	}
	if u.Scheme != "spiffe" {
		return nil, fmt.Errorf("invalid spiffe id %q: scheme must be spiffe", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid spiffe id %q: missing trust domain", raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("invalid spiffe id %q: userinfo not allowed", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return nil, fmt.Errorf("invalid spiffe id %q: query/fragment/port not allowed", raw)
	}
	if strings.Contains(u.Host, "%") {
		return nil, fmt.Errorf("invalid spiffe id %q: escaped trust domain", raw)
	}
	return &SpiffeID{TrustDomain: u.Host, Path: u.Path, raw: raw}, nil
}

// SpiffeIDFromCert returns the first valid SPIFFE URI SAN in the leaf
// certificate.
func SpiffeIDFromCert(cert *x509.Certificate) (*SpiffeID, error) {
	if cert == nil {
		return nil, errors.New("no peer certificate")
	}
	var firstErr error
	for _, u := range cert.URIs {
		raw := u.String()
		if !strings.HasPrefix(raw, "spiffe://") {
			continue
		}
		id, err := ParseSpiffeID(raw)
		if err != nil {
			firstErr = err
			continue
		}
		return id, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, errors.New("client certificate carries no spiffe:// URI SAN")
}

// TenantFromSpiffe maps a verified SPIFFE ID to a tenant using, in order:
// exact-ID pin, trust-domain pin, /tenant/<name>/… path convention, then
// defaultTenant (which may be "" to reject).
func TenantFromSpiffe(cfg *Config, id *SpiffeID) string {
	if t := cfg.SpiffeTenants[id.String()]; t != "" {
		return t
	}
	if t := cfg.SpiffeTenants["spiffe://"+id.TrustDomain]; t != "" {
		return t
	}
	parts := strings.Split(strings.Trim(id.Path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "tenant" && parts[1] != "" {
		return parts[1]
	}
	return cfg.DefaultTenant
}
