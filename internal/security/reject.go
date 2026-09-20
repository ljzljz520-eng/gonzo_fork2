package security

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// Reject reasons. These are stable strings surfaced in logs, metrics and the
// dashboard rejections API.
const (
	ReasonUnauthenticated = "unauthenticated"
	ReasonUnauthorized    = "unauthorized"
	ReasonMessageSize     = "message_size"
	ReasonRequestRate     = "request_rate"
	ReasonLogRate         = "log_rate"
	ReasonCardinality     = "series_cardinality"
	ReasonQueueFull       = "parse_queue_full"
	ReasonStorageQuota    = "storage_quota"
	ReasonBodyRead        = "body_read"
	ReasonDecode          = "decode"
	ReasonSinkError       = "sink_error"
)

// Reject is one observed denial event.
type Reject struct {
	Time      time.Time `json:"time"`
	Tenant    string    `json:"tenant"`
	Source    string    `json:"source"`
	Method    string    `json:"method"`
	Reason    string    `json:"reason"`
	Detail    string    `json:"detail"`
	Transport string    `json:"transport"` // "grpc" | "http" | "unix"
}

// TenantCounters are aggregate counters for one tenant.
type TenantCounters struct {
	Tenant  string           `json:"tenant"`
	Total   int64            `json:"total"`
	Reasons map[string]int64 `json:"reasons"`
}

// RejectStats is a point-in-time snapshot of denial activity.
type RejectStats struct {
	Total       int64                      `json:"total"`
	ByReason    map[string]int64           `json:"by_reason"`
	ByTenant    map[string]*TenantCounters `json:"by_tenant"`
	Recent      []Reject                   `json:"recent"`
	ObserveOnly bool                       `json:"observe_only"`
}

// RejectLogger records every denial three ways:
//   - a bounded in-memory ring of recent events (dashboard/admin API);
//   - aggregate counters by tenant and reason;
//   - one structured line to a Writer (stderr by default), so denials remain
//     visible even when the TUI redirects the standard logger to io.Discard.
type RejectLogger struct {
	mu          sync.Mutex
	ring        []Reject
	ringPos     int
	ringSize    int
	byReason    map[string]int64
	byTenant    map[string]*TenantCounters
	total       int64
	observeOnly bool
	w           io.Writer
}

// NewRejectLogger creates a RejectLogger keeping the most recent ringSize
// events and mirroring them to w (os.Stderr in production, nil in tests).
func NewRejectLogger(ringSize int, w io.Writer, observeOnly bool) *RejectLogger {
	if ringSize <= 0 {
		ringSize = 256
	}
	return &RejectLogger{
		ring:        make([]Reject, 0, ringSize),
		ringSize:    ringSize,
		byReason:    make(map[string]int64),
		byTenant:    make(map[string]*TenantCounters),
		observeOnly: observeOnly,
		w:           w,
	}
}

// Record stores and emits one rejection. It never blocks on the writer and
// is safe for concurrent use.
func (l *RejectLogger) Record(r Reject) {
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	if r.Tenant == "" {
		r.Tenant = "-"
	}

	l.mu.Lock()
	l.total++
	l.byReason[r.Reason]++
	tc := l.byTenant[r.Tenant]
	if tc == nil {
		tc = &TenantCounters{Tenant: r.Tenant, Reasons: make(map[string]int64)}
		l.byTenant[r.Tenant] = tc
	}
	tc.Total++
	tc.Reasons[r.Reason]++
	if len(l.ring) < l.ringSize {
		l.ring = append(l.ring, r)
	} else {
		l.ring[l.ringPos] = r
		l.ringPos = (l.ringPos + 1) % l.ringSize
	}
	w := l.w
	l.mu.Unlock()

	if w != nil {
		mode := "ENFORCE"
		if l.observeOnly {
			mode = "OBSERVE"
		}
		fmt.Fprintf(w, "[gonzo-security] mode=%s transport=%s tenant=%q source=%q auth=%s reason=%s detail=%s\n",
			mode, r.Transport, r.Tenant, r.Source, r.Method, r.Reason, r.Detail)
	}
}

// Snapshot returns a copy of current counters and the most recent events,
// newest first.
func (l *RejectLogger) Snapshot(limit int) RejectStats {
	l.mu.Lock()
	defer l.mu.Unlock()

	stats := RejectStats{
		Total:       l.total,
		ByReason:    make(map[string]int64, len(l.byReason)),
		ByTenant:    make(map[string]*TenantCounters, len(l.byTenant)),
		ObserveOnly: l.observeOnly,
	}
	for k, v := range l.byReason {
		stats.ByReason[k] = v
	}
	tenants := make([]string, 0, len(l.byTenant))
	for t, tc := range l.byTenant {
		cp := &TenantCounters{Tenant: t, Total: tc.Total, Reasons: make(map[string]int64, len(tc.Reasons))}
		for k, v := range tc.Reasons {
			cp.Reasons[k] = v
		}
		stats.ByTenant[t] = cp
		tenants = append(tenants, t)
	}
	sort.Strings(tenants)

	n := len(l.ring)
	if limit > 0 && limit < n {
		n = limit
	}
	stats.Recent = make([]Reject, 0, n)
	for i := 0; i < n; i++ {
		var idx int
		if len(l.ring) < l.ringSize {
			// Ring not yet wrapped: entries are in append order.
			idx = len(l.ring) - 1 - i
		} else {
			// Walk backwards from the slot just before the next write.
			idx = (l.ringPos - 1 - i) % l.ringSize
			for idx < 0 {
				idx += l.ringSize
			}
		}
		stats.Recent = append(stats.Recent, l.ring[idx])
	}
	return stats
}
