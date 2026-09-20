package engine

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/control-theory/gonzo/internal/ai"
	"github.com/control-theory/gonzo/internal/memory"
	"github.com/control-theory/gonzo/internal/tui"
)

// tenantState holds ALL mutable analysis data for one tenant. Its mutex is
// independent of other tenants, so an ingest storm in tenant A cannot block
// reads or ingestion for tenant B.
type tenantState struct {
	tenant     string
	mu         sync.RWMutex
	useLogTime bool
	stopWords  map[string]bool
	aiClient   aiClient

	maxBuffer int
	maxBytes  int64

	// Log buffer (ring) and current byte usage.
	buffer []tui.LogEntry
	bytes  int64

	// Severity tracking
	lifetimeSeverityCounts map[string]int64
	countsHistory          []tui.SeverityCounts
	severityTimeSeries     []SeverityTimePoint

	// Heatmap data (minute-by-minute severity counts)
	heatmapData []tui.HeatmapMinute

	// Pattern clustering
	drain3BySeverity map[string]*tui.Drain3Manager
	drain3All        *tui.Drain3Manager

	// Service tracking per severity
	servicesBySeverity map[string][]tui.ServiceCount

	// Dimension tracking
	lifetimeHostCounts    map[string]int64
	lifetimeServiceCounts map[string]int64
	lifetimeAttrKeyCounts map[string]map[string]int64

	// Frequency snapshot (latest)
	snapshot *memory.FrequencySnapshot

	// Word/attribute tracking
	lifetimeWordCounts map[string]int64
	lifetimeAttrCounts map[string]int64

	// Stream tracking
	streams map[string]*StreamInfo

	// Statistics
	statsStartTime time.Time
	totalLogsEver  int
	totalBytes     int64
}

// aiClient aliases the AI analysis interface used by summary queries.
type aiClient = ai.Client

func newTenantState(tenant string, maxBuffer int, maxBytes int64, stopWords map[string]bool, useLogTime bool) *tenantState {
	return &tenantState{
		tenant:                 tenant,
		useLogTime:             useLogTime,
		stopWords:              stopWords,
		maxBuffer:              maxBuffer,
		maxBytes:               maxBytes,
		buffer:                 make([]tui.LogEntry, 0, maxBuffer),
		lifetimeSeverityCounts: make(map[string]int64),
		countsHistory:          make([]tui.SeverityCounts, 0),
		severityTimeSeries:     make([]SeverityTimePoint, 0, 120),
		heatmapData:            make([]tui.HeatmapMinute, 0),
		drain3BySeverity:       tui.InitializeDrain3BySeverity(),
		drain3All:              tui.NewDrain3Manager(),
		servicesBySeverity:     make(map[string][]tui.ServiceCount),
		lifetimeHostCounts:     make(map[string]int64),
		lifetimeServiceCounts:  make(map[string]int64),
		lifetimeAttrKeyCounts:  make(map[string]map[string]int64),
		lifetimeWordCounts:     make(map[string]int64),
		lifetimeAttrCounts:     make(map[string]int64),
		streams:                make(map[string]*StreamInfo),
		statsStartTime:         time.Now(),
	}
}

// recordSize estimates the retained memory of one entry.
func recordSize(entry tui.LogEntry) int64 {
	n := int64(len(entry.RawLine) + len(entry.Message))
	for k, v := range entry.Attributes {
		n += int64(len(k) + len(v))
	}
	return n
}

// ingest is the single write path for one tenant's logs.
func (t *tenantState) ingest(entry tui.LogEntry) error {
	size := recordSize(entry)

	t.mu.Lock()
	defer t.mu.Unlock()

	// A single record larger than the whole tenant budget is rejected
	// outright; ring eviction could never make it fit.
	if t.maxBytes > 0 && size > t.maxBytes {
		return ErrStorageQuota
	}

	// Ring buffer with entry-count and byte budgets.
	t.buffer = append(t.buffer, entry)
	t.bytes += size
	for {
		if len(t.buffer) <= t.maxBuffer && (t.maxBytes <= 0 || t.bytes <= t.maxBytes) {
			break
		}
		if len(t.buffer) <= 1 {
			break // never evict the just-admitted record itself
		}
		t.bytes -= recordSize(t.buffer[0])
		t.buffer = t.buffer[1:]
	}

	// Lifetime statistics
	t.totalLogsEver++
	t.totalBytes += int64(len(entry.RawLine))
	t.lifetimeSeverityCounts[entry.Severity]++

	if host := entry.Attributes["host"]; host != "" {
		t.lifetimeHostCounts[host]++
	}
	if serviceName := getServiceName(entry); serviceName != "" && serviceName != "unknown" {
		t.lifetimeServiceCounts[serviceName]++
	}

	for key, value := range entry.Attributes {
		attrKey := fmt.Sprintf("%s=%s", key, value)
		if len(attrKey) < 200 {
			t.lifetimeAttrCounts[attrKey]++
		}
		if t.lifetimeAttrKeyCounts[key] == nil {
			t.lifetimeAttrKeyCounts[key] = make(map[string]int64)
		}
		t.lifetimeAttrKeyCounts[key][value]++
	}

	words := fields(entry.Message)
	for _, word := range words {
		if !t.stopWords[word] {
			t.lifetimeWordCounts[word]++
		}
	}

	t.updateHeatmapData(entry)
	t.updateServicesBySeverity(entry)

	if drain3Instance, exists := t.drain3BySeverity[entry.Severity]; exists && drain3Instance != nil {
		drain3Instance.AddLogMessage(entry.Message)
	}
	if t.drain3All != nil {
		t.drain3All.AddLogMessage(entry.Message)
	}

	t.updateStreamTracking(entry)
	return nil
}

// fields is the stop-word-aware tokenizer previously inlined in Ingest.
func fields(message string) []string {
	var out []string
	for _, word := range strings.Fields(strings.ToLower(message)) {
		if len(word) < 2 || len(word) > 50 {
			continue
		}
		word = strings.Trim(word, ".,!?;:()[]{}\"'")
		if len(word) >= 3 {
			out = append(out, word)
		}
	}
	return out
}

func (t *tenantState) ingestSeverityCounts(counts tui.SeverityCounts) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.countsHistory = append(t.countsHistory, counts)
	if len(t.countsHistory) > 50 {
		t.countsHistory = t.countsHistory[1:]
	}

	point := SeverityTimePoint{
		Timestamp: time.Now().Unix(),
		Counts: map[string]int{
			"FATAL": counts.Fatal,
			"ERROR": counts.Error,
			"WARN":  counts.Warn,
			"INFO":  counts.Info,
			"DEBUG": counts.Debug,
			"TRACE": counts.Trace,
		},
		Total: counts.Total,
	}
	t.severityTimeSeries = append(t.severityTimeSeries, point)
	if len(t.severityTimeSeries) > 120 {
		t.severityTimeSeries = t.severityTimeSeries[len(t.severityTimeSeries)-120:]
	}
}

func (t *tenantState) updateSnapshot(snapshot *memory.FrequencySnapshot) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.snapshot = snapshot
}

func (t *tenantState) stats() EngineStats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return EngineStats{
		Tenant:        t.tenant,
		StartTime:     t.statsStartTime,
		TotalLogsEver: t.totalLogsEver,
		TotalBytes:    t.totalBytes,
		BufferSize:    t.maxBuffer,
		BufferUsed:    len(t.buffer),
		BufferBytes:   t.bytes,
	}
}

// registerStream explicitly registers a stream for the tenant.
func (t *tenantState) registerStream(source, stream string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := source + ":" + stream
	if _, ok := t.streams[key]; !ok {
		t.streams[key] = &StreamInfo{
			Source:   source,
			Stream:   stream,
			LogCount: 0,
			LastSeen: time.Now(),
			Active:   true,
		}
	}
}

func (t *tenantState) markStreamInactive(source, stream string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s, ok := t.streams[source+":"+stream]; ok {
		s.Active = false
	}
}

// updateHeatmapData updates minute-by-minute heatmap data.
func (t *tenantState) updateHeatmapData(entry tui.LogEntry) {
	ts := entry.Timestamp
	if t.useLogTime && !entry.OrigTimestamp.IsZero() {
		ts = entry.OrigTimestamp
	}
	entryTime := ts.Truncate(time.Minute)

	var targetMinute *tui.HeatmapMinute
	for i := range t.heatmapData {
		if t.heatmapData[i].Timestamp.Equal(entryTime) {
			targetMinute = &t.heatmapData[i]
			break
		}
	}
	if targetMinute == nil {
		t.heatmapData = append(t.heatmapData, tui.HeatmapMinute{
			Timestamp: entryTime,
			Counts:    tui.SeverityCounts{},
		})
		targetMinute = &t.heatmapData[len(t.heatmapData)-1]
	}

	switch entry.Severity {
	case "TRACE":
		targetMinute.Counts.Trace++
	case "DEBUG":
		targetMinute.Counts.Debug++
	case "INFO":
		targetMinute.Counts.Info++
	case "WARN", "WARNING":
		targetMinute.Counts.Warn++
	case "ERROR":
		targetMinute.Counts.Error++
	case "FATAL":
		targetMinute.Counts.Fatal++
	case "CRITICAL":
		targetMinute.Counts.Critical++
	default:
		targetMinute.Counts.Unknown++
	}
	targetMinute.Counts.Total++

	// Prune old data (keep 6 hours).
	cutoffTime := time.Now().Add(-6 * time.Hour)
	filtered := t.heatmapData[:0]
	for _, minute := range t.heatmapData {
		if minute.Timestamp.After(cutoffTime) {
			filtered = append(filtered, minute)
		}
	}
	t.heatmapData = filtered
}

// updateServicesBySeverity keeps the top-10 services per severity.
func (t *tenantState) updateServicesBySeverity(entry tui.LogEntry) {
	severity := entry.Severity
	if severity == "" {
		severity = "UNKNOWN"
	}
	serviceName := getServiceName(entry)
	if serviceName == "" || serviceName == "unknown" {
		return
	}
	if t.servicesBySeverity[severity] == nil {
		t.servicesBySeverity[severity] = make([]tui.ServiceCount, 0)
	}
	found := false
	for i := range t.servicesBySeverity[severity] {
		if t.servicesBySeverity[severity][i].Service == serviceName {
			t.servicesBySeverity[severity][i].Count++
			found = true
			break
		}
	}
	if !found {
		t.servicesBySeverity[severity] = append(t.servicesBySeverity[severity], tui.ServiceCount{
			Service: serviceName,
			Count:   1,
		})
	}
	services := t.servicesBySeverity[severity]
	sortByCountDesc(services)
	if len(services) > 10 {
		t.servicesBySeverity[severity] = services[:10]
	}
}

// updateStreamTracking updates the tenant's stream registry.
func (t *tenantState) updateStreamTracking(entry tui.LogEntry) {
	source := "stdin"
	stream := "stdin"

	if ns := entry.Attributes["k8s.namespace"]; ns != "" {
		source = "k8s"
		if pod := entry.Attributes["k8s.pod"]; pod != "" {
			stream = ns + "/" + pod
		} else {
			stream = ns
		}
	} else if svc := entry.Attributes["service.name"]; svc != "" {
		source = "otlp"
		stream = svc
	} else if filename := entry.Attributes["source_file"]; filename != "" {
		source = "file"
		stream = filename
	}

	key := source + ":" + stream
	if s, ok := t.streams[key]; ok {
		s.LogCount++
		s.LastSeen = time.Now()
	} else {
		t.streams[key] = &StreamInfo{
			Source:   source,
			Stream:   stream,
			LogCount: 1,
			LastSeen: time.Now(),
			Active:   true,
		}
	}
}
