package security

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"
)

// IngestJob is one authenticated export moving through the parse pipeline.
// Payload is opaque to the security package (the receiver stores the
// decoded OTLP request); the Sink performs the CPU-heavy conversion.
type IngestJob struct {
	Identity *Identity
	Payload  interface{}
	reply    chan error
}

// Done returns the per-job result channel.
func (j *IngestJob) Done() <-chan error { return j.reply }

// Sink performs the actual, potentially expensive conversion/indexing of an
// authenticated export. It is always invoked from a scheduler worker.
type Sink interface {
	IngestLogs(ctx context.Context, id *Identity, payload interface{}) error
}

// Scheduler drains bounded per-tenant queues with round-robin fairness into
// a fixed worker pool. A tenant whose queue is full gets immediate
// ResourceExhausted: its backlog can never consume worker slots or queue
// capacity belonging to another tenant.
type Scheduler struct {
	limiter *Limiter
	sink    Sink
	rejects *RejectLogger
	workers int

	mu      sync.Mutex
	tenants []string // known tenants with queues (sorted)
	jobs    chan *IngestJob
	kick    chan struct{}

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewScheduler wires the scheduler. workers <= 0 means runtime.NumCPU().
func NewScheduler(parent context.Context, limiter *Limiter, sink Sink, rejects *RejectLogger, workers int) *Scheduler {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers < 1 {
		workers = 1
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Scheduler{
		limiter: limiter,
		sink:    sink,
		rejects: rejects,
		workers: workers,
		jobs:    make(chan *IngestJob, workers),
		kick:    make(chan struct{}, 1),
		ctx:     ctx,
		cancel:  cancel,
	}
	return s
}

// Start launches workers and the fairness dispatcher.
func (s *Scheduler) Start() {
	for range s.workers {
		s.wg.Go(func() {
			for {
				select {
				case <-s.ctx.Done():
					return
				case job := <-s.jobs:
					s.runJob(job)
				}
			}
		})
	}
	s.wg.Go(s.dispatch)
}

func (s *Scheduler) runJob(job *IngestJob) {
	err := s.sink.IngestLogs(s.ctx, job.Identity, job.Payload)
	if err != nil {
		reason := ReasonSinkError
		var qErr *QuotaError
		if errors.As(err, &qErr) {
			reason = qErr.Reason
		}
		s.rejects.Record(Reject{
			Tenant:    job.Identity.Tenant,
			Source:    job.Identity.Source,
			Method:    job.Identity.Method,
			Transport: "sink",
			Reason:    reason,
			Detail:    err.Error(),
		})
	}
	select {
	case job.reply <- err:
	case <-s.ctx.Done():
	}
}

// Submit enqueues an export for the identity's tenant. It never blocks:
// when the tenant queue is saturated it immediately returns a
// ResourceExhausted QuotaError.
func (s *Scheduler) Submit(id *Identity, payload interface{}, transport string) (*IngestJob, error) {
	q := s.limiter.Queue(id)
	job := &IngestJob{Identity: id, Payload: payload, reply: make(chan error, 1)}

	s.registerTenant(id.Tenant)

	select {
	case q <- job:
	default:
		err := &QuotaError{
			Reason: ReasonQueueFull,
			Detail: fmt.Sprintf("tenant %q parse queue depth %d saturated; retry with backoff",
				id.Tenant, cap(q)),
		}
		s.rejects.Record(Reject{
			Tenant:    id.Tenant,
			Source:    id.Source,
			Method:    id.Method,
			Transport: transport,
			Reason:    err.Reason,
			Detail:    err.Detail,
		})
		return nil, err
	}

	select {
	case s.kick <- struct{}{}:
	default:
	}
	return job, nil
}

func (s *Scheduler) registerTenant(tenant string) {
	s.mu.Lock()
	for _, t := range s.tenants {
		if t == tenant {
			s.mu.Unlock()
			return
		}
	}
	s.tenants = append(s.tenants, tenant)
	sort.Strings(s.tenants)
	s.mu.Unlock()
}

// dispatch services one queued job per tenant per round, rotating the start
// position so no tenant is permanently favored.
func (s *Scheduler) dispatch() {
	var rotation int
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()

	for {
		worked := s.dispatchRound(&rotation)
		if worked {
			continue
		}
		select {
		case <-s.ctx.Done():
			return
		case <-s.kick:
		case <-tick.C:
		}
	}
}

func (s *Scheduler) dispatchRound(rotation *int) bool {
	s.mu.Lock()
	tenants := make([]string, len(s.tenants))
	copy(tenants, s.tenants)
	s.mu.Unlock()
	if len(tenants) == 0 {
		return false
	}
	if *rotation >= len(tenants) {
		*rotation = 0
	}

	worked := false
	for i := range tenants {
		tenant := tenants[(*rotation+i)%len(tenants)]
		q := s.limiter.Queue(&Identity{Tenant: tenant})
		select {
		case job := <-q:
			select {
			case s.jobs <- job:
				worked = true
			default:
				// Worker pool saturated; re-queue this tenant's job at the
				// front by pushing back and end the round so we re-spin.
				select {
				case q <- job:
				default:
					// The tenant's consumer goroutine vanished between
					// operations; fail the job rather than dropping silently.
					select {
					case job.reply <- &QuotaError{Reason: ReasonQueueFull, Detail: "scheduler shutdown race"}:
					default:
					}
				}
				*rotation = (*rotation + i + 1) % max(len(tenants), 1)
				return worked
			}
		default:
		}
	}
	*rotation = (*rotation + 1) % max(len(tenants), 1)
	return worked
}

// Wait blocks until the scheduler is stopped and all workers exit.
func (s *Scheduler) Wait() {
	s.cancel()
	s.wg.Wait()
}
