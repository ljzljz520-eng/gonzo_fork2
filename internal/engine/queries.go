package engine

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/control-theory/gonzo/internal/memory"
	"github.com/control-theory/gonzo/internal/tui"
)

// Every read method below follows the same pattern:
//
//  1. resolveTenant() forces an authenticated scope — no scope, no data;
//  2. the resolved tenant (never the client-supplied filter) selects state;
//  3. the tenantState method does the actual work under that tenant's lock.
//
// There is intentionally no cross-tenant aggregation path: queries can
// never silently mix environments.

func (e *Engine) GetAllLogEntries(ctx context.Context) ([]tui.LogEntry, error) {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return nil, err
	}
	return e.stateForRead(tenant).allLogEntries(), nil
}

func (e *Engine) GetLogEntryCount(ctx context.Context) (int, error) {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return 0, err
	}
	return e.stateForRead(tenant).logEntryCount(), nil
}

func (e *Engine) GetHeatmapData(ctx context.Context) ([]tui.HeatmapMinute, error) {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return nil, err
	}
	return e.stateForRead(tenant).heatmapCopy(), nil
}

func (e *Engine) GetSeverityTimeSeries(ctx context.Context) ([]SeverityTimePoint, error) {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return nil, err
	}
	return e.stateForRead(tenant).severityTimeSeriesAll(), nil
}

func (e *Engine) QuerySeverityTimeSeries(ctx context.Context, filters InsightsFilters) []SeverityTimePoint {
	tenant, err := resolveTenant(ctx, filters.Tenant)
	if err != nil {
		return nil
	}
	return e.stateForRead(tenant).querySeverityTimeSeries(filters)
}

func (e *Engine) GetDrain3BySeverity(ctx context.Context) map[string]*tui.Drain3Manager {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return nil
	}
	return e.stateForRead(tenant).drain3BySeverity
}

func (e *Engine) GetServicesBySeverity(ctx context.Context) map[string][]tui.ServiceCount {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return nil
	}
	return e.stateForRead(tenant).servicesBySeverityCopy()
}

func (e *Engine) GetCountsHistory(ctx context.Context) []tui.SeverityCounts {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return nil
	}
	return e.stateForRead(tenant).countsHistoryCopy()
}

func (e *Engine) GetFrequencySnapshot(ctx context.Context) *memory.FrequencySnapshot {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return nil
	}
	return e.stateForRead(tenant).snapshot
}

func (e *Engine) GetLifetimeSeverityCounts(ctx context.Context) map[string]int64 {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return nil
	}
	return e.stateForRead(tenant).severityCountsCopy()
}

func (e *Engine) GetLifetimeHostCounts(ctx context.Context) map[string]int64 {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return nil
	}
	return e.stateForRead(tenant).hostCountsCopy()
}

func (e *Engine) GetLifetimeServiceCounts(ctx context.Context) map[string]int64 {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return nil
	}
	return e.stateForRead(tenant).serviceCountsCopy()
}

func (e *Engine) GetLifetimeAttrCounts(ctx context.Context) map[string]int64 {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return nil
	}
	return e.stateForRead(tenant).attrCountsCopy()
}

func (e *Engine) GetLifetimeWordCounts(ctx context.Context) map[string]int64 {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return nil
	}
	return e.stateForRead(tenant).wordCountsCopy()
}

func (e *Engine) GetLifetimeAttrKeyCounts(ctx context.Context) map[string]map[string]int64 {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return nil
	}
	return e.stateForRead(tenant).attrKeyCountsCopy()
}

// GetStats returns statistics for the scoped tenant.
func (e *Engine) GetStats(ctx context.Context) (EngineStats, error) {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return EngineStats{}, err
	}
	return e.stateForRead(tenant).stats(), nil
}

// GetStreams returns streams for the scoped tenant.
func (e *Engine) GetStreams(ctx context.Context) ([]StreamInfo, error) {
	tenant, err := resolveTenant(ctx, "")
	if err != nil {
		return nil, err
	}
	return e.stateForRead(tenant).streamsCopy(), nil
}

func (e *Engine) QueryLogSamples(ctx context.Context, filters InsightsFilters) ([]LogSample, error) {
	tenant, err := resolveTenant(ctx, filters.Tenant)
	if err != nil {
		return nil, err
	}
	return e.stateForRead(tenant).queryLogSamples(filters), nil
}

func (e *Engine) QuerySeverityData(ctx context.Context, filters InsightsFilters) ([]SeverityGroup, error) {
	tenant, err := resolveTenant(ctx, filters.Tenant)
	if err != nil {
		return nil, err
	}
	return e.stateForRead(tenant).querySeverityData(filters), nil
}

func (e *Engine) QuerySentimentData(ctx context.Context, filters InsightsFilters) (*SentimentData, error) {
	tenant, err := resolveTenant(ctx, filters.Tenant)
	if err != nil {
		return nil, err
	}
	return e.stateForRead(tenant).querySentimentData(filters), nil
}

func (e *Engine) QueryPatterns(ctx context.Context, filters InsightsFilters) ([]PatternGroup, error) {
	tenant, err := resolveTenant(ctx, filters.Tenant)
	if err != nil {
		return nil, err
	}
	return e.stateForRead(tenant).queryPatterns(filters), nil
}

func (e *Engine) QueryClasses(ctx context.Context, filters InsightsFilters) ([]ClassItem, error) {
	tenant, err := resolveTenant(ctx, filters.Tenant)
	if err != nil {
		return nil, err
	}
	return e.stateForRead(tenant).queryClasses(filters), nil
}

func (e *Engine) QuerySummary(ctx context.Context, filters InsightsFilters) (string, error) {
	tenant, err := resolveTenant(ctx, filters.Tenant)
	if err != nil {
		return "", err
	}
	return e.stateForRead(tenant).querySummary(filters, e.aiClient)
}

func (e *Engine) GetSentimentHeatmap(ctx context.Context, filters InsightsFilters) (string, error) {
	tenant, err := resolveTenant(ctx, filters.Tenant)
	if err != nil {
		return "", err
	}
	return e.stateForRead(tenant).sentimentHeatmap(filters), nil
}

func (e *Engine) GetAnomalies(ctx context.Context, filters InsightsFilters) (string, error) {
	tenant, err := resolveTenant(ctx, filters.Tenant)
	if err != nil {
		return "", err
	}
	return e.stateForRead(tenant).anomalies(filters), nil
}

func (e *Engine) QueryInsightsParams(ctx context.Context, filters InsightsFilters) (*InsightsParams, error) {
	tenant, err := resolveTenant(ctx, filters.Tenant)
	if err != nil {
		return nil, err
	}
	return e.stateForRead(tenant).insightsParams(), nil
}

// --- tenantState read methods ---

func (t *tenantState) allLogEntries() []tui.LogEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]tui.LogEntry, len(t.buffer))
	copy(result, t.buffer)
	return result
}

func (t *tenantState) logEntryCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.buffer)
}

func (t *tenantState) heatmapCopy() []tui.HeatmapMinute {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]tui.HeatmapMinute, len(t.heatmapData))
	copy(result, t.heatmapData)
	return result
}

func (t *tenantState) severityTimeSeriesAll() []SeverityTimePoint {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]SeverityTimePoint, len(t.severityTimeSeries))
	copy(result, t.severityTimeSeries)
	return result
}

func (t *tenantState) servicesBySeverityCopy() map[string][]tui.ServiceCount {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make(map[string][]tui.ServiceCount, len(t.servicesBySeverity))
	for k, v := range t.servicesBySeverity {
		copied := make([]tui.ServiceCount, len(v))
		copy(copied, v)
		result[k] = copied
	}
	return result
}

func (t *tenantState) countsHistoryCopy() []tui.SeverityCounts {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]tui.SeverityCounts, len(t.countsHistory))
	copy(result, t.countsHistory)
	return result
}

func (t *tenantState) severityCountsCopy() map[string]int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make(map[string]int64, len(t.lifetimeSeverityCounts))
	for k, v := range t.lifetimeSeverityCounts {
		result[k] = v
	}
	return result
}

func (t *tenantState) hostCountsCopy() map[string]int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make(map[string]int64, len(t.lifetimeHostCounts))
	for k, v := range t.lifetimeHostCounts {
		result[k] = v
	}
	return result
}

func (t *tenantState) serviceCountsCopy() map[string]int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make(map[string]int64, len(t.lifetimeServiceCounts))
	for k, v := range t.lifetimeServiceCounts {
		result[k] = v
	}
	return result
}

func (t *tenantState) attrCountsCopy() map[string]int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make(map[string]int64, len(t.lifetimeAttrCounts))
	for k, v := range t.lifetimeAttrCounts {
		result[k] = v
	}
	return result
}

func (t *tenantState) wordCountsCopy() map[string]int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make(map[string]int64, len(t.lifetimeWordCounts))
	for k, v := range t.lifetimeWordCounts {
		result[k] = v
	}
	return result
}

func (t *tenantState) attrKeyCountsCopy() map[string]map[string]int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make(map[string]map[string]int64, len(t.lifetimeAttrKeyCounts))
	for k, v := range t.lifetimeAttrKeyCounts {
		inner := make(map[string]int64, len(v))
		for ik, iv := range v {
			inner[ik] = iv
		}
		result[k] = inner
	}
	return result
}

func (t *tenantState) streamsCopy() []StreamInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]StreamInfo, 0, len(t.streams))
	for _, s := range t.streams {
		result = append(result, *s)
	}
	return result
}

// filterEntries applies InsightsFilters within the tenant's ring buffer.
// Must be called with the tenant read lock held.
func (t *tenantState) filterEntries(filters InsightsFilters) []tui.LogEntry {
	result := make([]tui.LogEntry, 0, len(t.buffer))
	for _, entry := range t.buffer {
		ts := entry.Timestamp
		if t.useLogTime && !entry.OrigTimestamp.IsZero() {
			ts = entry.OrigTimestamp
		}
		if filters.Start != nil && ts.Unix() < *filters.Start {
			continue
		}
		if filters.End != nil && ts.Unix() > *filters.End {
			continue
		}
		if filters.Severity != nil && *filters.Severity != "" {
			if !strings.EqualFold(entry.Severity, *filters.Severity) {
				continue
			}
		}
		if filters.Search != nil && *filters.Search != "" {
			search := strings.ToLower(*filters.Search)
			if !strings.Contains(strings.ToLower(entry.Message), search) &&
				!strings.Contains(strings.ToLower(entry.RawLine), search) {
				found := false
				for _, v := range entry.Attributes {
					if strings.Contains(strings.ToLower(v), search) {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}
		}
		if !matchesDimensionFilter(entry, filters) {
			continue
		}
		result = append(result, entry)
	}
	return result
}

func (t *tenantState) queryLogSamples(filters InsightsFilters) []LogSample {
	t.mu.RLock()
	defer t.mu.RUnlock()

	filtered := t.filterEntries(filters)
	limit := len(filtered)
	if filters.Limit != nil && *filters.Limit > 0 && *filters.Limit < limit {
		limit = *filters.Limit
	}
	start := len(filtered) - limit
	if start < 0 {
		start = 0
	}

	samples := make([]LogSample, 0, limit)
	for _, entry := range filtered[start:] {
		ts := entry.Timestamp.Unix()
		if t.useLogTime && !entry.OrigTimestamp.IsZero() {
			ts = entry.OrigTimestamp.Unix()
		}
		samples = append(samples, LogSample{
			Timestamp:  ts,
			Severity:   entry.Severity,
			Message:    entry.Message,
			Attributes: entry.Attributes,
			RawLine:    entry.RawLine,
		})
	}
	return samples
}

func (t *tenantState) querySeverityTimeSeries(filters InsightsFilters) []SeverityTimePoint {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if filters.Search == nil && filters.Severity == nil && filters.Start == nil && filters.End == nil {
		result := make([]SeverityTimePoint, len(t.severityTimeSeries))
		copy(result, t.severityTimeSeries)
		return result
	}

	filtered := t.filterEntries(filters)
	if len(filtered) == 0 {
		return nil
	}
	buckets := make(map[int64]map[string]int)
	for _, entry := range filtered {
		ts := entry.Timestamp.Unix()
		if t.useLogTime && !entry.OrigTimestamp.IsZero() {
			ts = entry.OrigTimestamp.Unix()
		}
		if buckets[ts] == nil {
			buckets[ts] = make(map[string]int)
		}
		sev := strings.ToUpper(entry.Severity)
		if sev == "" {
			sev = "INFO"
		}
		buckets[ts][sev]++
	}
	timestamps := make([]int64, 0, len(buckets))
	for ts := range buckets {
		timestamps = append(timestamps, ts)
	}
	sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })

	result := make([]SeverityTimePoint, 0, len(timestamps))
	for _, ts := range timestamps {
		counts := buckets[ts]
		total := 0
		for _, c := range counts {
			total += c
		}
		result = append(result, SeverityTimePoint{Timestamp: ts, Counts: counts, Total: total})
	}
	return result
}

func (t *tenantState) querySeverityData(filters InsightsFilters) []SeverityGroup {
	t.mu.RLock()
	defer t.mu.RUnlock()

	filtered := t.filterEntries(filters)
	groupBy := filters.GroupBy
	if groupBy == "" {
		groupBy = "service"
	}
	groups := make(map[string]map[string]int)
	for _, entry := range filtered {
		groupVal := getGroupValue(entry, groupBy)
		if groups[groupVal] == nil {
			groups[groupVal] = make(map[string]int)
		}
		groups[groupVal][entry.Severity]++
	}
	result := make([]SeverityGroup, 0, len(groups))
	for groupVal, counts := range groups {
		total := 0
		for _, c := range counts {
			total += c
		}
		result = append(result, SeverityGroup{GroupValue: groupVal, Counts: counts, Total: total})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Total > result[j].Total })
	return result
}

func (t *tenantState) querySentimentData(filters InsightsFilters) *SentimentData {
	t.mu.RLock()
	defer t.mu.RUnlock()

	filtered := t.filterEntries(filters)
	groupBy := filters.GroupBy
	if groupBy == "" {
		groupBy = "service"
	}
	type bucketKey struct {
		second   int64
		groupVal string
	}
	buckets := make(map[bucketKey][]float64)
	groupValueSet := make(map[string]bool)

	for _, entry := range filtered {
		groupVal := getGroupValue(entry, groupBy)
		groupValueSet[groupVal] = true
		ts := entry.Timestamp
		if t.useLogTime && !entry.OrigTimestamp.IsZero() {
			ts = entry.OrigTimestamp
		}
		key := bucketKey{second: ts.Unix(), groupVal: groupVal}
		buckets[key] = append(buckets[key], severityToSentiment(entry.Severity))
	}

	groupValues := make([]string, 0, len(groupValueSet))
	for gv := range groupValueSet {
		groupValues = append(groupValues, gv)
	}
	sort.Strings(groupValues)

	sentimentBuckets := make([]SentimentBucket, 0, len(buckets))
	for key, sentiments := range buckets {
		avg := 0.0
		for _, s := range sentiments {
			avg += s
		}
		avg /= float64(len(sentiments))
		sentimentBuckets = append(sentimentBuckets, SentimentBucket{
			Timestamp:  key.second,
			GroupValue: key.groupVal,
			Sentiment:  avg,
			LogCount:   len(sentiments),
		})
	}
	return &SentimentData{GroupValues: groupValues, Buckets: sentimentBuckets}
}

func (t *tenantState) queryPatterns(filters InsightsFilters) []PatternGroup {
	t.mu.RLock()
	defer t.mu.RUnlock()

	groupBy := filters.GroupBy
	if groupBy == "" {
		groupBy = "service"
	}
	limit := 20
	if filters.Limit != nil && *filters.Limit > 0 {
		limit = *filters.Limit
	}

	if groupBy == "severity" {
		result := make([]PatternGroup, 0)
		for severity, dm := range t.drain3BySeverity {
			if dm == nil {
				continue
			}
			patterns := dm.GetTopPatterns(limit)
			if len(patterns) == 0 {
				continue
			}
			items := make([]PatternItem, len(patterns))
			for i, p := range patterns {
				items[i] = PatternItem{Pattern: p.Template, Count: p.Count, Percentage: p.Percentage}
			}
			result = append(result, PatternGroup{GroupValue: severity, Patterns: items})
		}
		return result
	}

	var patterns []tui.PatternInfo
	if t.drain3All != nil {
		patterns = t.drain3All.GetTopPatterns(limit)
	}
	items := make([]PatternItem, len(patterns))
	for i, p := range patterns {
		items[i] = PatternItem{Pattern: p.Template, Count: p.Count, Percentage: p.Percentage}
	}
	return []PatternGroup{{GroupValue: "all", Patterns: items}}
}

func (t *tenantState) queryClasses(filters InsightsFilters) []ClassItem {
	t.mu.RLock()
	defer t.mu.RUnlock()

	filtered := t.filterEntries(filters)
	classCounts := make(map[string]int)
	for _, entry := range filtered {
		classCounts[entry.Severity]++
	}
	total := len(filtered)
	result := make([]ClassItem, 0, len(classCounts))
	for name, count := range classCounts {
		pct := 0.0
		if total > 0 {
			pct = float64(count) * 100.0 / float64(total)
		}
		result = append(result, ClassItem{Name: name, Count: count, Percentage: pct})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Count > result[j].Count })
	if filters.Limit != nil && *filters.Limit > 0 && len(result) > *filters.Limit {
		result = result[:*filters.Limit]
	}
	return result
}

func (t *tenantState) querySummary(filters InsightsFilters, ai aiClient) (string, error) {
	t.mu.RLock()
	entries := t.filterEntries(filters)
	severityCounts := make(map[string]int)
	for _, entry := range entries {
		severityCounts[entry.Severity]++
	}
	totalLogs := len(entries)
	drain3All := t.drain3All
	statsStartTime := t.statsStartTime
	maxLogBuffer := t.maxBuffer
	bufferLen := len(t.buffer)
	t.mu.RUnlock()

	if ai == nil {
		return t.statisticalSummary(totalLogs, severityCounts, entries, drain3All, statsStartTime, maxLogBuffer, bufferLen), nil
	}

	var sb strings.Builder
	sb.WriteString("Analyze these log entries and provide a brief summary of key issues, patterns, and recommendations.\n\n")
	sb.WriteString(fmt.Sprintf("Tenant: %s\n", t.tenant))
	sb.WriteString(fmt.Sprintf("Total logs: %d\n", totalLogs))
	sb.WriteString("Severity distribution:\n")
	for sev, count := range severityCounts {
		sb.WriteString(fmt.Sprintf("  %s: %d\n", sev, count))
	}
	sb.WriteString("\nRecent log samples:\n")
	sampleCount := min(50, len(entries))
	start := len(entries) - sampleCount
	for _, entry := range entries[start:] {
		sb.WriteString(fmt.Sprintf("[%s] %s\n", entry.Severity, entry.Message))
	}
	result, err := ai.AnalyzeLog(sb.String(), "SUMMARY", time.Now().Format(time.RFC3339), nil)
	if err != nil {
		return "", fmt.Errorf("AI analysis failed: %w", err)
	}
	return result, nil
}

func (t *tenantState) statisticalSummary(totalLogs int, severityCounts map[string]int, entries []tui.LogEntry, drain3All *tui.Drain3Manager, statsStartTime time.Time, maxLogBuffer, bufferLen int) string {
	var sb strings.Builder
	sb.WriteString("## Log Analysis Summary (Statistical)\n\n")
	sb.WriteString(fmt.Sprintf("**Tenant:** %s\n\n", t.tenant))
	sb.WriteString(fmt.Sprintf("**Total logs analyzed:** %d\n\n", totalLogs))
	sb.WriteString("### Severity Distribution\n")
	for sev, count := range severityCounts {
		pct := float64(count) * 100.0 / float64(max(totalLogs, 1))
		sb.WriteString(fmt.Sprintf("- %s: %d (%.1f%%)\n", sev, count, pct))
	}
	sb.WriteString("\n### Top Patterns\n")
	if drain3All != nil {
		patterns := drain3All.GetTopPatterns(5)
		for i, p := range patterns {
			sb.WriteString(fmt.Sprintf("%d. `%s` (%d occurrences, %.1f%%)\n", i+1, p.Template, p.Count, p.Percentage))
		}
	}
	if len(entries) > 0 {
		uptime := time.Since(statsStartTime).Round(time.Second)
		sb.WriteString(fmt.Sprintf("\n**Uptime:** %s | **Buffer:** %d/%d\n", uptime, bufferLen, maxLogBuffer))
	}
	sb.WriteString("\n*Note: AI analysis is not configured. Set up an AI provider for deeper insights.*\n")
	return sb.String()
}

func (t *tenantState) sentimentHeatmap(filters InsightsFilters) string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	filtered := t.filterEntries(filters)
	groupBy := filters.GroupBy
	if groupBy == "" {
		groupBy = "service"
	}
	type cellKey struct {
		minute   time.Time
		groupVal string
	}
	cells := make(map[cellKey][]float64)
	groupValueSet := make(map[string]bool)
	var minTime, maxTime time.Time

	for _, entry := range filtered {
		groupVal := getGroupValue(entry, groupBy)
		groupValueSet[groupVal] = true
		ts := entry.Timestamp
		if t.useLogTime && !entry.OrigTimestamp.IsZero() {
			ts = entry.OrigTimestamp
		}
		minute := ts.Truncate(time.Minute)
		if minTime.IsZero() || minute.Before(minTime) {
			minTime = minute
		}
		if maxTime.IsZero() || minute.After(maxTime) {
			maxTime = minute
		}
		cells[cellKey{minute: minute, groupVal: groupVal}] = append(cells[cellKey{minute: minute, groupVal: groupVal}], severityToSentiment(entry.Severity))
	}
	if len(cells) == 0 {
		return "No data available for heatmap."
	}

	groupValues := make([]string, 0, len(groupValueSet))
	for gv := range groupValueSet {
		groupValues = append(groupValues, gv)
	}
	sort.Strings(groupValues)

	var sb strings.Builder
	sb.WriteString("Sentiment Heatmap (+ positive, . neutral, - negative)\n\n")
	maxLabelLen := 0
	for _, gv := range groupValues {
		if len(gv) > maxLabelLen {
			maxLabelLen = len(gv)
		}
	}
	if maxLabelLen > 20 {
		maxLabelLen = 20
	}
	for _, gv := range groupValues {
		label := gv
		if len(label) > maxLabelLen {
			label = label[:maxLabelLen]
		}
		sb.WriteString(fmt.Sprintf("%-*s │", maxLabelLen, label))
		tt := minTime
		for !tt.After(maxTime) {
			if sentiments, ok := cells[cellKey{minute: tt, groupVal: gv}]; ok {
				avg := 0.0
				for _, s := range sentiments {
					avg += s
				}
				avg /= float64(len(sentiments))
				sb.WriteByte(sentimentToChar(avg))
			} else {
				sb.WriteByte(' ')
			}
			tt = tt.Add(time.Minute)
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

func (t *tenantState) anomalies(filters InsightsFilters) string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	filtered := t.filterEntries(filters)
	if len(filtered) == 0 {
		return "No log data available for anomaly detection."
	}

	var sb strings.Builder
	sb.WriteString("# Anomaly Detection Report\n\n")
	fatalCount, errorCount := 0, 0
	for _, entry := range filtered {
		switch entry.Severity {
		case "FATAL", "CRITICAL":
			fatalCount++
		case "ERROR":
			errorCount++
		}
	}
	if fatalCount > 0 {
		sb.WriteString(fmt.Sprintf("## Fatal/Critical Logs Detected\n- **%d** fatal/critical log entries found\n\n", fatalCount))
	}
	totalCount := len(filtered)
	if totalCount > 0 {
		errorRate := float64(errorCount) * 100.0 / float64(totalCount)
		if errorRate > 10 {
			sb.WriteString(fmt.Sprintf("## High Error Rate\n- Error rate: **%.1f%%** (%d/%d logs)\n\n", errorRate, errorCount, totalCount))
		}
	}
	recentCutoff := time.Now().Add(-5 * time.Minute)
	recentErrors, recentTotal := 0, 0
	for _, entry := range filtered {
		ts := entry.Timestamp
		if t.useLogTime && !entry.OrigTimestamp.IsZero() {
			ts = entry.OrigTimestamp
		}
		if ts.After(recentCutoff) {
			recentTotal++
			if entry.Severity == "ERROR" || entry.Severity == "FATAL" || entry.Severity == "CRITICAL" {
				recentErrors++
			}
		}
	}
	if recentTotal > 0 {
		recentErrorRate := float64(recentErrors) * 100.0 / float64(recentTotal)
		overallErrorRate := float64(errorCount+fatalCount) * 100.0 / float64(totalCount)
		if recentErrorRate > overallErrorRate*2 && recentErrors > 5 {
			sb.WriteString(fmt.Sprintf("## Error Spike Detected\n- Last 5 minutes: **%.1f%%** error rate (%d errors in %d logs)\n- Overall: **%.1f%%** error rate\n\n",
				recentErrorRate, recentErrors, recentTotal, overallErrorRate))
		}
	}
	type serviceStats struct{ sentiments []float64 }
	serviceMap := make(map[string]*serviceStats)
	for _, entry := range filtered {
		svc := getServiceName(entry)
		if svc == "" || svc == "unknown" {
			continue
		}
		if serviceMap[svc] == nil {
			serviceMap[svc] = &serviceStats{}
		}
		serviceMap[svc].sentiments = append(serviceMap[svc].sentiments, severityToSentiment(entry.Severity))
	}
	for svc, stats := range serviceMap {
		if len(stats.sentiments) < 10 {
			continue
		}
		mean := 0.0
		for _, s := range stats.sentiments {
			mean += s
		}
		mean /= float64(len(stats.sentiments))
		if mean < -0.3 {
			sb.WriteString(fmt.Sprintf("## Negative Sentiment: %s\n- Mean sentiment: **%.2f** (%.0f logs)\n\n", svc, mean, float64(len(stats.sentiments))))
		}
	}
	if sb.Len() == len("# Anomaly Detection Report\n\n") {
		sb.WriteString("No anomalies detected in the current data.\n")
	}
	return sb.String()
}

func (t *tenantState) insightsParams() *InsightsParams {
	t.mu.RLock()
	defer t.mu.RUnlock()

	params := &InsightsParams{TotalLogs: int64(t.totalLogsEver)}
	for host := range t.lifetimeHostCounts {
		params.Hosts = append(params.Hosts, host)
	}
	for svc := range t.lifetimeServiceCounts {
		params.Services = append(params.Services, svc)
	}
	for sev := range t.lifetimeSeverityCounts {
		params.Severities = append(params.Severities, sev)
	}
	dimKeys := map[string]*[]string{
		"k8s.namespace":  &params.Namespaces,
		"k8s.pod":        &params.Pods,
		"k8s.deployment": &params.Deployments,
		"environment":    &params.Environments,
		"env":            &params.Environments,
		"cluster":        &params.Clusters,
	}
	for key, target := range dimKeys {
		if vals, ok := t.lifetimeAttrKeyCounts[key]; ok {
			for val := range vals {
				*target = append(*target, val)
			}
		}
	}
	if len(t.buffer) > 0 {
		first := t.buffer[0].Timestamp.Unix()
		last := t.buffer[len(t.buffer)-1].Timestamp.Unix()
		params.OldestLog = &first
		params.NewestLog = &last
	}
	sort.Strings(params.Hosts)
	sort.Strings(params.Services)
	sort.Strings(params.Severities)
	sort.Strings(params.Namespaces)
	sort.Strings(params.Pods)
	sort.Strings(params.Deployments)
	sort.Strings(params.Environments)
	sort.Strings(params.Clusters)
	return params
}

// --- shared helpers (tenant-agnostic) ---

func matchesDimensionFilter(entry tui.LogEntry, filters InsightsFilters) bool {
	if filters.Namespaces != nil && len(*filters.Namespaces) > 0 {
		if !containsString(*filters.Namespaces, entry.Attributes["k8s.namespace"]) {
			return false
		}
	}
	if filters.Pods != nil && len(*filters.Pods) > 0 {
		if !containsString(*filters.Pods, entry.Attributes["k8s.pod"]) {
			return false
		}
	}
	if filters.Hosts != nil && len(*filters.Hosts) > 0 {
		if !containsString(*filters.Hosts, entry.Attributes["host"]) {
			return false
		}
	}
	if filters.Services != nil && len(*filters.Services) > 0 {
		if !containsString(*filters.Services, getServiceName(entry)) {
			return false
		}
	}
	if filters.Environments != nil && len(*filters.Environments) > 0 {
		env := entry.Attributes["environment"]
		if env == "" {
			env = entry.Attributes["env"]
		}
		if !containsString(*filters.Environments, env) {
			return false
		}
	}
	if filters.Clusters != nil && len(*filters.Clusters) > 0 {
		if !containsString(*filters.Clusters, entry.Attributes["cluster"]) {
			return false
		}
	}
	if filters.Deployments != nil && len(*filters.Deployments) > 0 {
		if !containsString(*filters.Deployments, entry.Attributes["k8s.deployment"]) {
			return false
		}
	}
	return true
}

func getGroupValue(entry tui.LogEntry, groupBy string) string {
	switch groupBy {
	case "service":
		return getServiceName(entry)
	case "host":
		if h := entry.Attributes["host"]; h != "" {
			return h
		}
		return "unknown"
	case "severity":
		return entry.Severity
	case "namespace":
		if ns := entry.Attributes["k8s.namespace"]; ns != "" {
			return ns
		}
		return "default"
	case "pod":
		if pod := entry.Attributes["k8s.pod"]; pod != "" {
			return pod
		}
		return "unknown"
	case "deployment":
		if dep := entry.Attributes["k8s.deployment"]; dep != "" {
			return dep
		}
		return "unknown"
	case "env", "environment":
		if env := entry.Attributes["environment"]; env != "" {
			return env
		}
		if env := entry.Attributes["env"]; env != "" {
			return env
		}
		return "default"
	case "cluster":
		if cl := entry.Attributes["cluster"]; cl != "" {
			return cl
		}
		return "default"
	case "category":
		return entry.Severity
	default:
		return getServiceName(entry)
	}
}

func getServiceName(entry tui.LogEntry) string {
	for _, key := range []string{"service", "service.name", "serviceName", "app", "application"} {
		if svc := entry.Attributes[key]; svc != "" {
			return svc
		}
	}
	if host := entry.Attributes["host"]; host != "" {
		return "host:" + host
	}
	return "unknown"
}

func severityToSentiment(severity string) float64 {
	switch strings.ToUpper(severity) {
	case "FATAL", "CRITICAL":
		return -1.0
	case "ERROR":
		return -0.6
	case "WARN", "WARNING":
		return 0.0
	case "INFO":
		return 0.5
	case "DEBUG":
		return 0.7
	case "TRACE":
		return 0.9
	default:
		return 0.0
	}
}

func sentimentToChar(sentiment float64) byte {
	if sentiment > 0.3 {
		return '+'
	}
	if sentiment < -0.3 {
		return '-'
	}
	return '.'
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if strings.EqualFold(item, s) {
			return true
		}
	}
	return false
}

func sortByCountDesc(services []tui.ServiceCount) {
	sort.Slice(services, func(i, j int) bool { return services[i].Count > services[j].Count })
}
