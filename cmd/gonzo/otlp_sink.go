package main

import (
	"context"
	"errors"
	"fmt"

	otlpgrpc "go.opentelemetry.io/proto/otlp/collector/logs/v1"

	"github.com/control-theory/gonzo/internal/engine"
	"github.com/control-theory/gonzo/internal/security"
	"github.com/control-theory/gonzo/internal/tui"
)

// buildOTLPSecurityConfig assembles the effective security configuration
// from the optional YAML block (otlp-security) and CLI overrides. Defaults
// bind loopback only; see security.Config.Normalize.
func buildOTLPSecurityConfig() *security.Config {
	sc := cfg.OTLPSecurity
	if sc == nil {
		sc = &security.Config{}
	}
	if cfg.OTLPGRPCAddr != "" {
		sc.GRPCAddr = cfg.OTLPGRPCAddr
	} else if sc.GRPCAddr == "" {
		sc.GRPCAddr = fmt.Sprintf("127.0.0.1:%d", cfg.OTLPGRPCPort)
	}
	if cfg.OTLPHTTPAddr != "" {
		sc.HTTPAddr = cfg.OTLPHTTPAddr
	} else if sc.HTTPAddr == "" {
		sc.HTTPAddr = fmt.Sprintf("127.0.0.1:%d", cfg.OTLPHTTPPort)
	}
	if cfg.OTLPUnixSocket != "" {
		sc.UnixSocket = cfg.OTLPUnixSocket
	}
	if cfg.OTLPObserveOnly {
		sc.ObserveOnly = true
	}
	if cfg.OTLPDefaultTenant != "" {
		sc.DefaultTenant = cfg.OTLPDefaultTenant
	}
	_ = sc.Normalize() // flags/config defaults are valid; receiver re-validates
	return sc
}

// securityMethodsConfigured reports whether any network authentication
// method is configured (otherwise the web dashboard uses local-console mode).
func securityMethodsConfigured(sc *security.Config) bool {
	return sc.TLS != nil || sc.OIDC != nil || len(sc.APITokens) > 0
}

// otlpIngestSink converts authenticated OTLP exports directly into
// tenant-scoped tui.LogEntry values and indexes them in the engine. It runs
// on scheduler workers (one fixed pool, fair per-tenant dispatch), so the
// CPU-heavy conversion never happens inline on the gRPC/HTTP goroutines.
type otlpIngestSink struct {
	eng     *engine.Engine
	display chan<- *tui.LogEntry // optional local TUI display feed
}

// IngestLogs implements security.Sink.
func (s *otlpIngestSink) IngestLogs(_ context.Context, id *security.Identity, payload interface{}) error {
	req, ok := payload.(*otlpgrpc.ExportLogsServiceRequest)
	if !ok {
		return &security.QuotaError{
			Reason: security.ReasonDecode,
			Detail: "sink received unexpected payload type",
		}
	}

	for _, resourceLogs := range req.ResourceLogs {
		// Start from attacker-controlled resource attributes, then let the
		// authenticated identity overwrite same-named keys and stamp
		// gonzo.tenant/gonzo.source/gonzo.auth_method. Any client-supplied
		// gonzo.* key is dropped here, and again after record attributes
		// are merged below.
		resourceAttrs := make(map[string]string)
		if resourceLogs.Resource != nil {
			for _, attr := range resourceLogs.Resource.Attributes {
				if attr.Key != "" && attr.Value != nil {
					resourceAttrs[attr.Key] = extractStringFromAnyValue(attr.Value)
				}
			}
		}
		security.StampIdentity(id, resourceAttrs)

		for _, scopeLogs := range resourceLogs.ScopeLogs {
			for _, record := range scopeLogs.LogRecords {
				entry := extractLogEntryFromOTLPRecordWithResource(record, resourceAttrs)
				if entry == nil {
					continue
				}
				// Record attributes were merged with precedence inside the
				// extractor; re-stamp so a forged record-level
				// gonzo.tenant/service.name can never win.
				security.StampIdentity(id, entry.Attributes)
				entry.Tenant = id.Tenant

				if err := s.eng.Ingest(*entry); err != nil {
					if errors.Is(err, engine.ErrStorageQuota) {
						// Fail the export so the exporter retries; the
						// scheduler records this as an observable rejection.
						return &security.QuotaError{
							Reason: security.ReasonStorageQuota,
							Detail: err.Error(),
						}
					}
					return err
				}

				// Best-effort mirror to the local operator TUI. A slow TUI
				// can never apply backpressure to ingestion.
				if s.display != nil {
					select {
					case s.display <- entry:
					default:
					}
				}
			}
		}
	}
	return nil
}

// storageQuotaAdapter bridges security.Limiter storage limits to the
// engine's StorageQuotaProvider interface.
type storageQuotaAdapter struct {
	limiter *security.Limiter
}

func (a *storageQuotaAdapter) LimitsFor(tenant string) (int, int64) {
	l := a.limiter.LimitsFor(tenant)
	return l.MaxEntries, l.MaxBytes
}
