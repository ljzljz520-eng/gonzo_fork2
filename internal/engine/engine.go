package engine

import (
	"errors"
	"sync"
	"time"

	"github.com/control-theory/gonzo/internal/ai"
	"github.com/control-theory/gonzo/internal/memory"
	"github.com/control-theory/gonzo/internal/tui"
)

// ErrStorageQuota is returned when a single record exceeds the tenant's
// byte budget. The web/ingest layer maps it to an observable rejection.
var ErrStorageQuota = errors.New("tenant storage quota exceeded")

// StorageQuotaProvider supplies per-tenant retention limits. The security
// limiter implements it; a nil provider falls back to the engine default
// buffer size.
type StorageQuotaProvider interface {
	LimitsFor(tenant string) (maxEntries int, maxBytes int64)
}

// Engine is the shared, concurrency-safe analysis state. All state is
// sharded by tenant: each tenantState has its own ring buffer, indexes and
// lock, so a burst from one tenant never blocks another tenant's ingestion
// or queries. Every read path requires an authenticated Scope.
type Engine struct {
	// mu guards only the tenants map.
	mu      sync.RWMutex
	tenants map[string]*tenantState

	defaultBuffer int
	stopWords     map[string]bool
	aiClient      ai.Client
	useLogTime    bool
	quotas        StorageQuotaProvider

	statsStartTime time.Time
}

// NewEngine creates a new Engine with the given default per-tenant buffer.
func NewEngine(maxLogBuffer int, stopWords map[string]bool, aiClient ai.Client, useLogTime bool) *Engine {
	return &Engine{
		tenants:        make(map[string]*tenantState),
		defaultBuffer:  maxLogBuffer,
		stopWords:      stopWords,
		aiClient:       aiClient,
		useLogTime:     useLogTime,
		statsStartTime: time.Now(),
	}
}

// SetStorageQuotaProvider attaches per-tenant retention limits. Must be
// called before ingestion starts.
func (e *Engine) SetStorageQuotaProvider(q StorageQuotaProvider) {
	e.quotas = q
}

func (e *Engine) limitsFor(tenant string) (int, int64) {
	if e.quotas != nil {
		if n, b := e.quotas.LimitsFor(tenant); n > 0 {
			return n, b
		}
	}
	return e.defaultBuffer, 0
}

// stateFor returns the existing tenant state or nil.
func (e *Engine) stateFor(tenant string) *tenantState {
	e.mu.RLock()
	t := e.tenants[tenant]
	e.mu.RUnlock()
	return t
}

// stateForRead returns tenant state for reads, creating an empty state so
// callers can uniformly query a tenant that has not produced traffic yet.
func (e *Engine) stateForRead(tenant string) *tenantState {
	if t := e.stateFor(tenant); t != nil {
		return t
	}
	maxEntries, maxBytes := e.limitsFor(tenant)
	t := newTenantState(tenant, maxEntries, maxBytes, e.stopWords, e.useLogTime)
	e.mu.Lock()
	defer e.mu.Unlock()
	if existing, ok := e.tenants[tenant]; ok {
		return existing
	}
	e.tenants[tenant] = t
	return t
}

func (e *Engine) stateForWrite(tenant string) *tenantState {
	if t := e.stateFor(tenant); t != nil {
		return t
	}
	maxEntries, maxBytes := e.limitsFor(tenant)
	t := newTenantState(tenant, maxEntries, maxBytes, e.stopWords, e.useLogTime)
	e.mu.Lock()
	defer e.mu.Unlock()
	if existing, ok := e.tenants[tenant]; ok {
		return existing
	}
	e.tenants[tenant] = t
	return t
}

// Ingest adds a log entry to the tenant named by entry.Tenant. This is the
// only write path for network/file logs. It returns ErrStorageQuota when a
// single record exceeds the tenant's byte budget; the caller records that
// rejection instead of admitting the record.
func (e *Engine) Ingest(entry tui.LogEntry) error {
	if entry.Tenant == "" {
		entry.Tenant = LocalTenant
	}
	t := e.stateForWrite(entry.Tenant)
	return t.ingest(entry)
}

// IngestSeverityCounts stores one interval's severity counts for a tenant.
func (e *Engine) IngestSeverityCounts(tenant string, counts tui.SeverityCounts) {
	if tenant == "" {
		tenant = LocalTenant
	}
	e.stateForWrite(tenant).ingestSeverityCounts(counts)
}

// UpdateFrequencySnapshot stores the latest frequency snapshot for a tenant.
func (e *Engine) UpdateFrequencySnapshot(tenant string, snapshot *memory.FrequencySnapshot) {
	if tenant == "" {
		tenant = LocalTenant
	}
	e.stateForWrite(tenant).updateSnapshot(snapshot)
}

// Reset clears all tenants.
func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tenants = make(map[string]*tenantState)
}

// ResetTenant clears a single tenant's state.
func (e *Engine) ResetTenant(tenant string) {
	e.mu.Lock()
	delete(e.tenants, tenant)
	e.mu.Unlock()
}

// ActiveTenants lists tenants currently holding state.
func (e *Engine) ActiveTenants() []string {
	e.mu.RLock()
	names := make([]string, 0, len(e.tenants))
	for name := range e.tenants {
		names = append(names, name)
	}
	e.mu.RUnlock()
	return names
}

// StatsFor returns statistics for one tenant without scope enforcement
// (used by the per-tenant WS broadcaster; the subscription itself is
// authenticated and tenant-bound).
func (e *Engine) StatsFor(tenant string) EngineStats {
	return e.stateForRead(tenant).stats()
}

// TenantInfos returns per-tenant usage for the admin status endpoint.
func (e *Engine) TenantInfos() []TenantInfo {
	e.mu.RLock()
	names := make([]string, 0, len(e.tenants))
	for name := range e.tenants {
		names = append(names, name)
	}
	e.mu.RUnlock()
	out := make([]TenantInfo, 0, len(names))
	for _, name := range names {
		s := e.stateForRead(name).stats()
		out = append(out, TenantInfo{
			Tenant:        name,
			TotalLogsEver: s.TotalLogsEver,
			BufferUsed:    s.BufferUsed,
			BufferBytes:   s.BufferBytes,
			BufferSize:    s.BufferSize,
		})
	}
	return out
}
