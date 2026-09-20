package security

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// oidcVerifier validates Bearer JWTs against an OIDC issuer's JWKS endpoint.
// JWKS documents are fetched lazily, cached and refreshed on unknown key IDs
// (key rotation). All verification is done with the Go standard library.
type oidcVerifier struct {
	cfg    *OIDCConfig
	client *http.Client

	mu       sync.Mutex
	jwksURL  string
	keys     map[string]jsonWebKey
	fetched  time.Time
	hmacKeys [][]byte
}

type jsonWebKey struct {
	kid string
	alg string
	key interface{} // *rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
}

type oidcDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

type jwksDoc struct {
	Keys []json.RawMessage `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func newOIDCVerifier(cfg *OIDCConfig) *oidcVerifier {
	v := &oidcVerifier{
		cfg:     cfg,
		client:  &http.Client{Timeout: 10 * time.Second},
		keys:    make(map[string]jsonWebKey),
		jwksURL: strings.TrimRight(cfg.JWKSURL, "/"),
	}
	for _, s := range cfg.HMACSecrets {
		v.hmacKeys = append(v.hmacKeys, []byte(s))
	}
	return v
}

func (v *oidcVerifier) verify(_ context.Context, raw string) (*Identity, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed jwt")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt header encoding: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("jwt header: %w", err)
	}
	if header.Alg == "" || header.Alg == "none" {
		return nil, errors.New("jwt alg none not allowed")
	}
	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt claims encoding: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(claimBytes, &claims); err != nil {
		return nil, fmt.Errorf("jwt claims: %w", err)
	}
	if err := v.verifySignature(header.Alg, header.Kid, parts[0]+"."+parts[1], parts[2]); err != nil {
		return nil, err
	}
	if err := validateClaims(v.cfg, claims); err != nil {
		return nil, err
	}

	tenant := claimString(claims, v.cfg.TenantClaim)
	if tenant == "" {
		for _, alt := range []string{"tenants", "tenant_id"} {
			if tenant = claimString(claims, alt); tenant != "" {
				break
			}
		}
	}
	// Tenant resolution (claim fallback vs. reject) is decided by the
	// Authenticator using the outer Config.DefaultTenant.

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, errors.New("token missing sub claim")
	}

	attrs := make(map[string]string)
	for claim, attrKey := range v.cfg.AttributeClaims {
		if val := claimString(claims, claim); val != "" {
			attrs[attrKey] = val
		}
	}

	return &Identity{
		Tenant:     tenant,
		Source:     "oidc:" + v.cfg.IssuerURL + "#" + sub,
		Method:     MethodOIDC,
		Attributes: attrs,
	}, nil
}

func claimString(claims map[string]interface{}, key string) string {
	v, ok := claims[key]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case []interface{}:
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func validateClaims(cfg *OIDCConfig, claims map[string]interface{}) error {
	now := time.Now()
	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(now) {
			return errors.New("token expired")
		}
	}
	if nbf, ok := claims["nbf"].(float64); ok {
		if time.Unix(int64(nbf), 0).After(now.Add(time.Minute)) {
			return errors.New("token not yet valid")
		}
	}
	iss, _ := claims["iss"].(string)
	if iss != "" && iss != cfg.IssuerURL && strings.TrimRight(iss, "/") != strings.TrimRight(cfg.IssuerURL, "/") {
		return fmt.Errorf("unexpected issuer %q", iss)
	}
	if len(cfg.Audiences) > 0 {
		if !audienceMatches(claims["aud"], cfg.Audiences) {
			return errors.New("token audience not allowed")
		}
	}
	return nil
}

func audienceMatches(raw interface{}, allowed []string) bool {
	want := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		want[a] = true
	}
	switch t := raw.(type) {
	case string:
		return want[t]
	case []interface{}:
		for _, item := range t {
			if s, ok := item.(string); ok && want[s] {
				return true
			}
		}
	}
	return false
}

func (v *oidcVerifier) verifySignature(alg, kid, signingInput, sigPart string) error {
	sig, err := base64.RawURLEncoding.DecodeString(sigPart)
	if err != nil {
		return fmt.Errorf("jwt signature encoding: %w", err)
	}

	if strings.HasPrefix(alg, "HS") {
		macOK := false
		for _, secret := range v.hmacKeys {
			var h func() crypto.Hash
			switch alg {
			case "HS256":
				h = func() crypto.Hash { return crypto.SHA256 }
			case "HS384":
				h = func() crypto.Hash { return crypto.SHA384 }
			case "HS512":
				h = func() crypto.Hash { return crypto.SHA512 }
			default:
				return fmt.Errorf("unsupported hmac alg %q", alg)
			}
			hh := h().New()
			hh.Write(secret)
			hh.Write([]byte(signingInput))
			if hmac.Equal(sig, hh.Sum(nil)) {
				macOK = true
				break
			}
		}
		if !macOK {
			return errors.New("jwt hmac signature mismatch")
		}
		return nil
	}

	key, err := v.keyFor(alg, kid)
	if err != nil {
		return err
	}

	var hash crypto.Hash
	var rsaPKCS, rsaPSS bool
	switch alg {
	case "RS256":
		hash, rsaPKCS = crypto.SHA256, true
	case "RS384":
		hash, rsaPKCS = crypto.SHA384, true
	case "RS512":
		hash, rsaPKCS = crypto.SHA512, true
	case "PS256":
		hash, rsaPSS = crypto.SHA256, true
	case "PS384":
		hash, rsaPSS = crypto.SHA384, true
	case "PS512":
		hash, rsaPSS = crypto.SHA512, true
	case "ES256":
		hash = crypto.SHA256
	case "ES384":
		hash = crypto.SHA384
	case "EdDSA":
		// no prehash
	default:
		return fmt.Errorf("unsupported jwt alg %q", alg)
	}

	switch pub := key.key.(type) {
	case *rsa.PublicKey:
		h := hash.New()
		h.Write([]byte(signingInput))
		digest := h.Sum(nil)
		if rsaPKCS {
			if err := rsa.VerifyPKCS1v15(pub, hash, digest, sig); err != nil {
				return fmt.Errorf("rsa signature: %w", err)
			}
			return nil
		}
		if rsaPSS {
			if err := rsa.VerifyPSS(pub, hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
				return fmt.Errorf("rsa-pss signature: %w", err)
			}
			return nil
		}
	case *ecdsa.PublicKey:
		r, s, ok := parseECDSA(sig)
		if !ok {
			return errors.New("invalid ecdsa signature encoding")
		}
		h := hash.New()
		h.Write([]byte(signingInput))
		if !ecdsa.Verify(pub, h.Sum(nil), r, s) {
			return errors.New("ecdsa signature mismatch")
		}
		return nil
	case ed25519.PublicKey:
		if alg != "EdDSA" {
			return fmt.Errorf("ed25519 key cannot be used with %q", alg)
		}
		if !ed25519.Verify(pub, []byte(signingInput), sig) {
			return errors.New("ed25519 signature mismatch")
		}
		return nil
	}
	return errors.New("jwt key type does not match alg")
}

// parseECDSA splits a fixed-size R||S ECDSA signature (JWA form).
func parseECDSA(sig []byte) (*big.Int, *big.Int, bool) {
	if len(sig)%2 != 0 {
		return nil, nil, false
	}
	half := len(sig) / 2
	return new(big.Int).SetBytes(sig[:half]), new(big.Int).SetBytes(sig[half:]), true
}

func (v *oidcVerifier) keyFor(alg, kid string) (jsonWebKey, error) {
	v.mu.Lock()
	if k, ok := v.keys[kid]; ok {
		v.mu.Unlock()
		return k, nil
	}
	needFetch := v.fetched.IsZero() || kid != ""
	v.mu.Unlock()

	if needFetch {
		if err := v.fetchJWKS(context.Background()); err != nil {
			return jsonWebKey{}, err
		}
		v.mu.Lock()
		if k, ok := v.keys[kid]; ok {
			v.mu.Unlock()
			return k, nil
		}
		v.mu.Unlock()
	}
	return jsonWebKey{}, fmt.Errorf("jwks has no key for kid=%q alg=%q", kid, alg)
}

func (v *oidcVerifier) fetchJWKS(ctx context.Context) error {
	jwksURL := v.jwksURL
	if jwksURL == "" {
		disc, err := v.discover(ctx)
		if err != nil {
			return err
		}
		jwksURL = strings.TrimRight(disc.JWKSURI, "/")
	}
	if jwksURL == "" {
		return errors.New("oidc: no jwks_uri available")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return err
	}
	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}

	keys := make(map[string]jsonWebKey, len(doc.Keys))
	for _, raw := range doc.Keys {
		k, err := parseJWK(raw)
		if err != nil {
			continue // skip unusable keys rather than failing the whole document
		}
		keys[k.kid] = k
	}
	if len(keys) == 0 {
		return errors.New("jwks document contained no usable keys")
	}

	v.mu.Lock()
	v.keys = keys
	v.jwksURL = jwksURL
	v.fetched = time.Now()
	v.mu.Unlock()
	return nil
}

func (v *oidcVerifier) discover(ctx context.Context) (*oidcDiscovery, error) {
	endpoint := strings.TrimRight(v.cfg.IssuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc discovery: status %d", resp.StatusCode)
	}
	var disc oidcDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&disc); err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	return &disc, nil
}

func parseJWK(raw json.RawMessage) (jsonWebKey, error) {
	var k jwk
	if err := json.Unmarshal(raw, &k); err != nil {
		return jsonWebKey{}, err
	}
	if k.Kid == "" {
		return jsonWebKey{}, errors.New("jwk missing kid")
	}
	switch k.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return jsonWebKey{}, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return jsonWebKey{}, err
		}
		exponent := 65537
		if len(eBytes) > 0 {
			exponent = int(binary.BigEndian.Uint64(append(make([]byte, 8-len(eBytes)), eBytes...)))
		}
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: exponent,
		}
		return jsonWebKey{kid: k.Kid, alg: k.Alg, key: pub}, nil
	case "EC":
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return jsonWebKey{}, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return jsonWebKey{}, err
		}
		pub := &ecdsa.PublicKey{
			X: new(big.Int).SetBytes(xBytes),
			Y: new(big.Int).SetBytes(yBytes),
		}
		switch k.Crv {
		case "P-256":
			pub.Curve = elliptic.P256()
		case "P-384":
			pub.Curve = elliptic.P384()
		default:
			return jsonWebKey{}, fmt.Errorf("unsupported ec curve %q", k.Crv)
		}
		return jsonWebKey{kid: k.Kid, alg: k.Alg, key: pub}, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return jsonWebKey{}, fmt.Errorf("unsupported okp curve %q", k.Crv)
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return jsonWebKey{}, err
		}
		if len(raw) != ed25519.PublicKeySize {
			return jsonWebKey{}, errors.New("bad ed25519 key length")
		}
		return jsonWebKey{kid: k.Kid, alg: k.Alg, key: ed25519.PublicKey(raw)}, nil
	default:
		return jsonWebKey{}, fmt.Errorf("unsupported jwk kty %q", k.Kty)
	}
}

// keyThumbprint returns a stable short hash of an identity source, used in
// per-token rate limiting where needed.
func keyThumbprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}
