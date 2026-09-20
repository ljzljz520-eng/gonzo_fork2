package security

import (
	"bytes"
	"strings"
	"testing"
)

func TestRejectLoggerSnapshotOrdering(t *testing.T) {
	r := NewRejectLogger(3, nil, false)
	for i := range 5 {
		r.Record(Reject{Reason: ReasonUnauthenticated, Detail: string(rune('a' + i))})
	}
	s := r.Snapshot(0)
	if s.Total != 5 || s.ByReason[ReasonUnauthenticated] != 5 {
		t.Fatalf("counters wrong: %+v", s)
	}
	if len(s.Recent) != 3 {
		t.Fatalf("ring size = %d, want 3", len(s.Recent))
	}
	// Newest first, wrapped ring keeps the last three (c, d, e).
	got := []string{s.Recent[0].Detail, s.Recent[1].Detail, s.Recent[2].Detail}
	want := []string{"e", "d", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("recent = %v, want %v", got, want)
		}
	}

	var buf bytes.Buffer
	rw := NewRejectLogger(4, &buf, true)
	rw.Record(Reject{Reason: ReasonUnauthorized, Tenant: "t", Detail: "x"})
	if !strings.Contains(buf.String(), "[gonzo-security] mode=OBSERVE") {
		t.Fatalf("structured line missing: %q", buf.String())
	}
	if !rw.Snapshot(0).ObserveOnly {
		t.Fatal("observe flag not surfaced")
	}
}
