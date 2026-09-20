package otlpreceiver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	otlpgrpc "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/control-theory/gonzo/internal/security"
)

type certPair struct {
	certPEM []byte
	keyPEM  []byte
}

// genTestPKI builds a CA, a server certificate (127.0.0.1/localhost) and a
// client certificate carrying a SPIFFE URI SAN.
func genTestPKI(t *testing.T, clientSpiffe string) (caPEM []byte, serverPair, clientPair certPair) {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gonzo-test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	must(err)
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	makeLeaf := func(commonName, spiffe string, dns []string, ips []net.IP, eku []x509.ExtKeyUsage) certPair {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		uri, err := url.Parse(spiffe)
		must(err)
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: commonName},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  eku,
			DNSNames:     dns,
			IPAddresses:  ips,
			URIs:         []*url.URL{uri},
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, caTpl, &key.PublicKey, caKey)
		must(err)
		keyDER, err := x509.MarshalECPrivateKey(key)
		must(err)
		return certPair{
			certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		}
	}

	serverPair = makeLeaf("gonzo-server", "spiffe://example.org/gonzo-server",
		[]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	clientPair = makeLeaf("collector", clientSpiffe,
		nil, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	return caPEM, serverPair, clientPair
}

func writeMTLSFiles(t *testing.T, caPEM []byte, srv, cli certPair) (certFile, keyFile, caFile string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	return write("server.crt", srv.certPEM), write("server.key", srv.keyPEM), write("ca.crt", caPEM)
}

func mtlsClientConn(t *testing.T, addr string, caPEM []byte, pair certPair) *grpc.ClientConn {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("ca pem unusable")
	}
	clientCert, err := cryptotls.X509KeyPair(pair.certPEM, pair.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	creds := credentials.NewTLS(&cryptotls.Config{
		RootCAs:      pool,
		Certificates: []cryptotls.Certificate{clientCert},
	})
	conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestMTLSSpiffeEndToEnd(t *testing.T) {
	const spiffeA = "spiffe://example.org/ns/prod/sa/collector"
	caPEM, srv, cli := genTestPKI(t, spiffeA)
	certFile, keyFile, caFile := writeMTLSFiles(t, caPEM, srv, cli)

	cfg := &security.Config{
		GRPCAddr: "127.0.0.1:0",
		HTTPAddr: "127.0.0.1:0",
		TLS: &security.TLSConfig{
			CertFile:     certFile,
			KeyFile:      keyFile,
			CAFile:       caFile,
			TrustDomains: []string{"example.org"},
		},
		SpiffeTenants: map[string]string{spiffeA: "team-a"},
	}
	r, sink, _ := startTestReceiver(t, cfg)

	conn := mtlsClientConn(t, r.listeners[0].Addr().String(), caPEM, cli)
	client := otlpgrpc.NewLogsServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := client.Export(ctx, protoExportRequest("svc-mtls")); err != nil {
		t.Fatalf("mTLS export: %v", err)
	}
	if tenants := sink.tenants(); len(tenants) != 1 || tenants[0] != "team-a" {
		t.Fatalf("sink tenants = %v, want [team-a]", tenants)
	}
	if methods := sink.methods(); methods[0] != security.MethodMTLSSPIFFE {
		t.Fatalf("method = %v, want mtls-spiffe", methods)
	}
}

func TestMTLSRejectsUntrustedTrustDomain(t *testing.T) {
	caPEM, srv, evilCli := genTestPKI(t, "spiffe://evil.org/ns/x/sa/rogue")
	certFile, keyFile, caFile := writeMTLSFiles(t, caPEM, srv, evilCli)

	cfg := &security.Config{
		GRPCAddr: "127.0.0.1:0",
		HTTPAddr: "127.0.0.1:0",
		TLS: &security.TLSConfig{
			CertFile:     certFile,
			KeyFile:      keyFile,
			CAFile:       caFile,
			TrustDomains: []string{"example.org"},
		},
	}
	r, sink, _ := startTestReceiver(t, cfg)

	conn := mtlsClientConn(t, r.listeners[0].Addr().String(), caPEM, evilCli)
	client := otlpgrpc.NewLogsServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := client.Export(ctx, protoExportRequest("svc-evil")); err == nil {
		t.Fatal("export with disallowed SPIFFE trust domain must fail")
	}
	if len(sink.tenants()) != 0 {
		t.Fatalf("rejected client reached the sink: %v", sink.tenants())
	}
}
