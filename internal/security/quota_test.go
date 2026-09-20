package security

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func smallQuotaConfig(t *testing.T) *Config {
	c := &Config{
		GRPCAddr: "127.0.0.1:0",
		HTTPAddr: "127.0.0.1:0",
		Quota: QuotaConfig{
			MaxMessageBytes:   50,
			RequestsPerSecond: 100,
			RequestBurst:      100,
			LogsPerSecond:     10,
			LogBurst:          10,
			MaxSeries:         2,
			SeriesTTL:         "80ms",
			QueueDepth:        2,
			MaxBufferEntries:  100,
			MaxBufferBytes:    4096,
		},
	}
	if err := c.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return c
}

func quotaErrReason(t *testing.T, err error) string {
	t.Helper()
	var qErr *QuotaError
	if !errors.As(err, &qErr) {
		t.Fatalf("expected QuotaError, got %v", err)
	}
	return qErr.Reason
}

func TestQuotaMessageSize(t *testing.T) {
	c := smallQuotaConfig(t)
	r := NewRejectLogger(32, nil, false)
	l := NewLimiter(c, r)
	id := &Identity{Tenant: "team-a", Method: MethodAPIToken}

	if err := l.CheckRequest(id, 40, 0, nil, "http"); err != nil {
		t.Fatalf("40 bytes under 50 limit rejected: %v", err)
	}
	err := l.CheckRequest(id, 51, 0, nil, "http")
	if reason := quotaErrReason(t, err); reason != ReasonMessageSize {
		t.Fatalf("reason = %s, want message_size", reason)
	}
	if got := r.Snapshot(0).ByReason[ReasonMessageSize]; got != 1 {
		t.Fatalf("rejection not recorded, counters=%v", r.Snapshot(0).ByReason)
	}
}

func TestQuotaRequestRate(t *testing.T) {
	c := smallQuotaConfig(t)
	c.Quota.RequestsPerSecond = 1
	c.Quota.RequestBurst = 1
	l := NewLimiter(c, NewRejectLogger(32, nil, false))
	id := &Identity{Tenant: "team-a"}
	if err := l.CheckRequest(id, 1, 0, nil, "grpc"); err != nil {
		t.Fatal(err)
	}
	if err := l.CheckRequest(id, 1, 0, nil, "grpc"); err == nil {
		t.Fatal("second request past burst=1 must be rejected")
	}
	// Another tenant is not affected by team-a's burst.
	other := &Identity{Tenant: "team-b"}
	if err := l.CheckRequest(other, 1, 0, nil, "grpc"); err != nil {
		t.Fatalf("other tenant rejected by team-a rate limit: %v", err)
	}
}

func TestQuotaLogRate(t *testing.T) {
	c := smallQuotaConfig(t)
	l := NewLimiter(c, NewRejectLogger(32, nil, false))
	id := &Identity{Tenant: "team-a"}
	err := l.CheckRequest(id, 1, 11, nil, "http") // burst 10
	if reason := quotaErrReason(t, err); reason != ReasonLogRate {
		t.Fatalf("reason = %s, want log_rate", reason)
	}
}

func TestQuotaSeriesCardinalityAndTTL(t *testing.T) {
	c := smallQuotaConfig(t)
	l := NewLimiter(c, NewRejectLogger(32, nil, false))
	id := &Identity{Tenant: "team-a"}

	keys := []string{
		SeriesKey(map[string]string{"service.name": "a"}),
		SeriesKey(map[string]string{"service.name": "b"}),
	}
	if err := l.CheckRequest(id, 1, 1, keys, "http"); err != nil {
		t.Fatalf("first two series rejected: %v", err)
	}
	err := l.CheckRequest(id, 1, 1,
		[]string{SeriesKey(map[string]string{"service.name": "c"})}, "http")
	if reason := quotaErrReason(t, err); reason != ReasonCardinality {
		t.Fatalf("reason = %s, want series_cardinality", reason)
	}

	// Re-seeing an existing series is fine.
	if err := l.CheckRequest(id, 1, 1,
		[]string{SeriesKey(map[string]string{"service.name": "a"})}, "http"); err != nil {
		t.Fatalf("existing series rejected: %v", err)
	}

	// After the TTL, idle series are swept and cardinality frees up.
	time.Sleep(120 * time.Millisecond)
	if err := l.CheckRequest(id, 1, 1,
		[]string{SeriesKey(map[string]string{"service.name": "c"})}, "http"); err != nil {
		t.Fatalf("post-TTL series rejected: %v", err)
	}
}

func TestStorageLimitsPerTenant(t *testing.T) {
	c := smallQuotaConfig(t)
	c.TenantOverrides = map[string]QuotaConfig{
		"big": {MaxBufferEntries: 5000, MaxBufferBytes: 1 << 30},
	}
	if err := c.Normalize(); err != nil {
		t.Fatal(err)
	}
	l := NewLimiter(c, NewRejectLogger(8, nil, false))
	if got := l.LimitsFor("big").MaxEntries; got != 5000 {
		t.Fatalf("override entries = %d", got)
	}
	if got := l.LimitsFor("team-a").MaxEntries; got != 100 {
		t.Fatalf("default entries = %d", got)
	}
}

type sinkFunc func(ctx context.Context, id *Identity, payload interface{}) error

func (f sinkFunc) IngestLogs(ctx context.Context, id *Identity, payload interface{}) error {
	return f(ctx, id, payload)
}

func TestSchedulerQueueFullImmediate(t *testing.T) {
	c := smallQuotaConfig(t) // queue depth 2
	r := NewRejectLogger(32, nil, false)
	l := NewLimiter(c, r)
	// Scheduler is never started: jobs stay in the bounded queue.
	s := NewScheduler(context.Background(), l, sinkFunc(func(context.Context, *Identity, interface{}) error {
		return nil
	}), r, 1)
	id := &Identity{Tenant: "team-a"}

	if _, err := s.Submit(id, "j1", "http"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(id, "j2", "http"); err != nil {
		t.Fatal(err)
	}
	_, err := s.Submit(id, "j3", "http")
	if reason := quotaErrReason(t, err); reason != ReasonQueueFull {
		t.Fatalf("third submit reason = %s, want parse_queue_full", reason)
	}
}

func TestSchedulerTenantIsolationUnderLoad(t *testing.T) {
	c := smallQuotaConfig(t)
	r := NewRejectLogger(32, nil, false)
	l := NewLimiter(c, r)

	blockA := make(chan struct{})
	var aGate atomic.Bool
	aGate.Store(true)
	gotB := make(chan struct{}, 1)
	sink := sinkFunc(func(ctx context.Context, id *Identity, payload interface{}) error {
		if id.Tenant == "a" {
			// Exactly one tenant-a job parks on a worker; subsequent a jobs
			// complete immediately so the pool stays available for others.
			if aGate.CompareAndSwap(true, false) {
				select {
				case <-blockA:
				case <-ctx.Done():
				}
			}
			return nil
		}
		close(gotB)
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewScheduler(ctx, l, sink, r, 2)
	s.Start()

	idA := &Identity{Tenant: "a"}
	idB := &Identity{Tenant: "b"}
	if _, err := s.Submit(idA, "a1", "http"); err != nil {
		t.Fatal(err)
	}
	// Flood tenant A. Its bounded queue must absorb backlog and reject the
	// overflow immediately with queue_full — never block shared workers.
	sawQueueFull := false
	for i := range 8 {
		if _, err := s.Submit(idA, fmt.Sprintf("a%d", i), "http"); err != nil {
			if reason := quotaErrReason(t, err); reason != ReasonQueueFull {
				t.Fatalf("a overflow reason = %s", reason)
			}
			sawQueueFull = true
		}
	}
	if !sawQueueFull {
		t.Fatal("expected at least one parse_queue_full rejection under flood")
	}

	// Tenant B's export must be processed while tenant A still holds one
	// worker and a full backlog: the fair rotation hands B the next free
	// worker rather than draining all of A's queue first.
	if _, err := s.Submit(idB, "b1", "http"); err != nil {
		t.Fatalf("tenant B submit blocked by tenant A backlog: %v", err)
	}
	select {
	case <-gotB:
	case <-time.After(3 * time.Second):
		t.Fatal("tenant B not processed while tenant A was saturated")
	}
	close(blockA)
}

func TestSchedulerSinkQuotaErrorRecordedWithReason(t *testing.T) {
	c := smallQuotaConfig(t)
	r := NewRejectLogger(32, nil, false)
	l := NewLimiter(c, r)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink := sinkFunc(func(context.Context, *Identity, interface{}) error {
		return &QuotaError{Reason: ReasonStorageQuota, Detail: "full"}
	})
	s := NewScheduler(ctx, l, sink, r, 1)
	s.Start()
	job, err := s.Submit(&Identity{Tenant: "a"}, "x", "http")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-job.Done():
		if e == nil || quotaErrReason(t, e) != ReasonStorageQuota {
			t.Fatalf("job err = %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("job not processed")
	}
	if got := r.Snapshot(0).ByReason[ReasonStorageQuota]; got != 1 {
		t.Fatalf("sink quota denial counters = %v, want storage_quota=1", r.Snapshot(0).ByReason)
	}
}
