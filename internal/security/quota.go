package security

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// StableSeriesAttrs are the resource-attribute keys treated as "series"
// dimensions for cardinality limiting. Both canonical OpenTelemetry names
// and common legacy keys are covered.
var StableSeriesAttrs = []string{
	"service.name",
	"service.namespace",
	"k8s.namespace.name",
	"k8s.pod.name",
	"k8s.deployment.name",
	"k8s.container.name",
	"host.name",
	"environment",
	"env",
	"cluster",
}

// ErrResourceExhausted marks a per-tenant quota denial. Callers map it to
// gRPC codes.ResourceExhausted / HTTP 429.
var ErrResourceExhausted = errors.New("resource exhausted")

// QuotaError is a typed per-tenant quota denial.
type QuotaError struct {
	Reason string
	Detail string
}

func (e *QuotaError) Error() string { return e.Reason + ": " + e.Detail }
func (e *QuotaError) Unwrap() error { return ErrResourceExhausted }

// Limiter owns per-tenant rate limiters, cardinality trackers and bounded
// parse queues. All state is keyed by authenticated tenant, never by
// client-supplied attributes.
type Limiter struct {
	cfg     *Config
	rejects *RejectLogger

	mu      sync.RWMutex
	tenants map[string]*tenantLimit
}

type tenantLimit struct {
	cfg        QuotaConfig
	reqLimiter *rate.Limiter
	logLimiter *rate.Limiter

	seriesMu  sync.Mutex
	series    map[string]time.Time
	seriesTTL time.Duration
	lastSweep time.Time

	queue chan *IngestJob
}

// NewLimiter creates a per-tenant quota limiter.
func NewLimiter(cfg *Config, rejects *RejectLogger) *Limiter {
	return &Limiter{
		cfg:     cfg,
		rejects: rejects,
		tenants: make(map[string]*tenantLimit),
	}
}

// tenant returns the lazily-created limiter state for a tenant.
func (l *Limiter) tenant(tenant string) *tenantLimit {
	l.mu.RLock()
	t, ok := l.tenants[tenant]
	l.mu.RUnlock()
	if ok {
		return t
	}
	q := l.cfg.QuotaFor(tenant)
	t = &tenantLimit{
		cfg:        q,
		reqLimiter: rate.NewLimiter(rate.Limit(q.RequestsPerSecond), q.RequestBurst),
		logLimiter: rate.NewLimiter(rate.Limit(q.LogsPerSecond), q.LogBurst),
		series:     make(map[string]time.Time),
		queue:      make(chan *IngestJob, q.QueueDepth),
	}
	ttl, err := time.ParseDuration(q.SeriesTTL)
	if err != nil || ttl <= 0 {
		ttl = 30 * time.Minute
	}
	t.seriesTTL = ttl

	l.mu.Lock()
	defer l.mu.Unlock()
	if existing, ok := l.tenants[tenant]; ok {
		return existing
	}
	l.tenants[tenant] = t
	return t
}

// SeriesKey builds a stable fingerprint for one ResourceLogs batch from its
// stringified resource attributes. Empty values are skipped.
func SeriesKey(resourceAttrs map[string]string) string {
	var b []byte
	for _, key := range StableSeriesAttrs {
		if v, ok := resourceAttrs[key]; ok && v != "" {
			b = append(b, key...)
			b = append(b, '=')
			b = append(b, v...)
			b = append(b, '|')
		}
	}
	if len(b) == 0 {
		return ""
	}
	return string(b)
}

// CheckRequest enforces message size, request rate, log rate and series
// cardinality for one authenticated export. It returns nil on acceptance.
// Denials are recorded on the RejectLogger.
func (l *Limiter) CheckRequest(id *Identity, msgBytes, nLogs int, seriesKeys []string, transport string) error {
	t := l.tenant(id.Tenant)

	if msgBytes > t.cfg.MaxMessageBytes {
		return l.deny(id, transport, ReasonMessageSize,
			fmt.Sprintf("message %d bytes exceeds tenant limit %d", msgBytes, t.cfg.MaxMessageBytes))
	}
	if !t.reqLimiter.Allow() {
		return l.deny(id, transport, ReasonRequestRate,
			fmt.Sprintf("request rate exceeds %.2f rps", t.cfg.RequestsPerSecond))
	}
	if nLogs > 0 && !t.logLimiter.AllowN(time.Now(), nLogs) {
		return l.deny(id, transport, ReasonLogRate,
			fmt.Sprintf("batch of %d logs exceeds rate %.2f logs/s (burst %d)", nLogs, t.cfg.LogsPerSecond, t.cfg.LogBurst))
	}
	if len(seriesKeys) > 0 {
		if err := t.checkSeries(id, seriesKeys, transport, l.rejects); err != nil {
			return err
		}
	}
	return nil
}

func (t *tenantLimit) checkSeries(id *Identity, keys []string, transport string, rejects *RejectLogger) error {
	t.seriesMu.Lock()
	defer t.seriesMu.Unlock()

	now := time.Now()
	if now.Sub(t.lastSweep) > t.seriesTTL {
		for k, seen := range t.series {
			if now.Sub(seen) > t.seriesTTL {
				delete(t.series, k)
			}
		}
		t.lastSweep = now
	}

	var newKeys int
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		if _, exists := t.series[k]; !exists {
			newKeys++
		}
	}
	if t.series != nil && len(t.series)+newKeys > t.cfg.MaxSeries {
		err := &QuotaError{
			Reason: ReasonCardinality,
			Detail: fmt.Sprintf("tenant %q series limit %d reached (%d new series rejected)",
				id.Tenant, t.cfg.MaxSeries, newKeys),
		}
		rejects.Record(Reject{
			Tenant:    id.Tenant,
			Source:    id.Source,
			Method:    id.Method,
			Transport: transport,
			Reason:    err.Reason,
			Detail:    err.Detail,
		})
		return err
	}
	for k := range seen {
		t.series[k] = now
	}
	return nil
}

func (l *Limiter) deny(id *Identity, transport, reason, detail string) error {
	l.rejects.Record(Reject{
		Tenant:    id.Tenant,
		Source:    id.Source,
		Method:    id.Method,
		Transport: transport,
		Reason:    reason,
		Detail:    detail,
	})
	return &QuotaError{Reason: reason, Detail: detail}
}

// Queue returns the bounded parse queue for a tenant. It is owned by the
// fair scheduler; reads/writes never block other tenants.
func (l *Limiter) Queue(id *Identity) chan *IngestJob {
	return l.tenant(id.Tenant).queue
}

// QueueDepth reports the configured per-tenant parse queue depth.
func (l *Limiter) QueueDepth(tenant string) int {
	return l.tenant(tenant).cfg.QueueDepth
}

// StorageLimits is consumed by the engine to bound per-tenant retained
// memory. Satisfies engine.StorageQuotaProvider.
type StorageLimits struct {
	MaxEntries int
	MaxBytes   int64
}

// LimitsFor returns the storage quota for a tenant.
func (l *Limiter) LimitsFor(tenant string) StorageLimits {
	q := l.cfg.QuotaFor(tenant)
	return StorageLimits{MaxEntries: q.MaxBufferEntries, MaxBytes: q.MaxBufferBytes}
}

// ActiveTenants returns a sorted snapshot of tenants that have produced
// traffic (used for fair scheduling and per-tenant broadcast ticking).
func (l *Limiter) ActiveTenants() []string {
	l.mu.RLock()
	names := make([]string, 0, len(l.tenants))
	for name := range l.tenants {
		names = append(names, name)
	}
	l.mu.RUnlock()
	sort.Strings(names)
	return names
}
