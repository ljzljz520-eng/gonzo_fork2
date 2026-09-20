package web

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/control-theory/gonzo/internal/engine"
)

// failOnScope maps engine scope errors to HTTP status codes. Every handler
// calls this immediately after deriving its scoped context, so a missing
// identity never reaches a query.
func failOnScope(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, engine.ErrTenantScopeRequired) {
		writeError(w, http.StatusUnauthorized, err.Error())
		return true
	}
	writeError(w, http.StatusForbidden, err.Error())
	return true
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx, id, ok := scopedContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	stats, err := s.engine.GetStats(ctx)
	if failOnScope(w, err) {
		return
	}
	streams, err := s.engine.GetStreams(ctx)
	if failOnScope(w, err) {
		return
	}

	uptime := time.Since(stats.StartTime).Round(time.Second).String()
	logRate := 0.0
	elapsed := time.Since(stats.StartTime).Seconds()
	if elapsed > 0 {
		logRate = float64(stats.TotalLogsEver) / elapsed
	}

	streamInfos := make([]engine.StreamInfo, len(streams))
	copy(streamInfos, streams)

	status := engine.StatusInfo{
		Tenant:       id.Tenant,
		Uptime:       uptime,
		TotalLogs:    int64(stats.TotalLogsEver),
		TotalBytes:   stats.TotalBytes,
		LogRate:      logRate,
		Streams:      streamInfos,
		BufferSize:   stats.BufferSize,
		BufferUsed:   stats.BufferUsed,
		AIConfigured: false,
	}
	if id.Admin {
		// Admins also see the list of active tenants on the status call.
		writeJSON(w, struct {
			engine.StatusInfo
			Tenants []engine.TenantInfo `json:"tenants,omitempty"`
		}{
			StatusInfo: status,
			Tenants:    s.engine.TenantInfos(),
		})
		return
	}
	writeJSON(w, status)
}

func (s *Server) handleSeverity(w http.ResponseWriter, r *http.Request) {
	ctx, _, ok := scopedContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	filters := parseFilters(r)
	data, err := s.engine.QuerySeverityData(ctx, filters)
	if failOnScope(w, err) {
		return
	}
	writeJSON(w, data)
}

func (s *Server) handleSentiment(w http.ResponseWriter, r *http.Request) {
	ctx, _, ok := scopedContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	filters := parseFilters(r)
	data, err := s.engine.QuerySentimentData(ctx, filters)
	if failOnScope(w, err) {
		return
	}
	writeJSON(w, data)
}

func (s *Server) handlePatterns(w http.ResponseWriter, r *http.Request) {
	ctx, _, ok := scopedContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	filters := parseFilters(r)
	data, err := s.engine.QueryPatterns(ctx, filters)
	if failOnScope(w, err) {
		return
	}
	writeJSON(w, data)
}

func (s *Server) handleClasses(w http.ResponseWriter, r *http.Request) {
	ctx, _, ok := scopedContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	filters := parseFilters(r)
	data, err := s.engine.QueryClasses(ctx, filters)
	if failOnScope(w, err) {
		return
	}
	writeJSON(w, data)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	ctx, _, ok := scopedContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	filters := parseFilters(r)
	data, err := s.engine.QueryLogSamples(ctx, filters)
	if failOnScope(w, err) {
		return
	}
	writeJSON(w, data)
}

func (s *Server) handleHeatmap(w http.ResponseWriter, r *http.Request) {
	ctx, _, ok := scopedContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	raw, err := s.engine.GetHeatmapData(ctx)
	if failOnScope(w, err) {
		return
	}
	// Convert tui.HeatmapMinute (struct fields) to engine.HeatmapMinuteData (map)
	data := make([]engine.HeatmapMinuteData, 0, len(raw))
	for _, m := range raw {
		counts := map[string]int{
			"FATAL": m.Counts.Fatal,
			"ERROR": m.Counts.Error,
			"WARN":  m.Counts.Warn,
			"INFO":  m.Counts.Info,
			"DEBUG": m.Counts.Debug,
			"TRACE": m.Counts.Trace,
		}
		data = append(data, engine.HeatmapMinuteData{
			Timestamp: m.Timestamp.Unix(),
			Counts:    counts,
		})
	}
	writeJSON(w, data)
}

func (s *Server) handleAnomalies(w http.ResponseWriter, r *http.Request) {
	ctx, _, ok := scopedContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	filters := parseFilters(r)
	report, err := s.engine.GetAnomalies(ctx, filters)
	if failOnScope(w, err) {
		return
	}
	writeJSON(w, map[string]string{"report": report})
}

func (s *Server) handleStreams(w http.ResponseWriter, r *http.Request) {
	ctx, _, ok := scopedContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	streams, err := s.engine.GetStreams(ctx)
	if failOnScope(w, err) {
		return
	}
	writeJSON(w, streams)
}

func (s *Server) handleInsightsParams(w http.ResponseWriter, r *http.Request) {
	ctx, _, ok := scopedContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	filters := parseFilters(r)
	params, err := s.engine.QueryInsightsParams(ctx, filters)
	if failOnScope(w, err) {
		return
	}
	writeJSON(w, params)
}

func (s *Server) handleSeverityTimeSeries(w http.ResponseWriter, r *http.Request) {
	ctx, _, ok := scopedContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	filters := parseFilters(r)
	writeJSON(w, s.engine.QuerySeverityTimeSeries(ctx, filters))
}

func (s *Server) handleTopAttributes(w http.ResponseWriter, r *http.Request) {
	ctx, _, ok := scopedContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	limitStr := r.URL.Query().Get("limit")
	limit := 20
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	attrKeyCounts := s.engine.GetLifetimeAttrKeyCounts(ctx)
	if attrKeyCounts == nil {
		writeError(w, http.StatusUnauthorized, "tenant scope required")
		return
	}
	stats, err := s.engine.GetStats(ctx)
	if failOnScope(w, err) {
		return
	}
	totalLogs := int64(stats.TotalLogsEver)

	// Flatten into entries and sort by count
	var entries []engine.AttributeEntry
	for key, vals := range attrKeyCounts {
		for val, count := range vals {
			pct := 0.0
			if totalLogs > 0 {
				pct = float64(count) * 100.0 / float64(totalLogs)
			}
			entries = append(entries, engine.AttributeEntry{
				Key:        key,
				Value:      val,
				Count:      count,
				Percentage: pct,
			})
		}
	}

	// Sort descending by count
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})

	if len(entries) > limit {
		entries = entries[:limit]
	}

	writeJSON(w, entries)
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	ctx, _, ok := scopedContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	filters := parseFilters(r)
	summary, err := s.engine.QuerySummary(ctx, filters)
	if failOnScope(w, err) {
		return
	}
	writeJSON(w, map[string]string{"summary": summary})
}

// parseFilters extracts InsightsFilters from query parameters.
func parseFilters(r *http.Request) engine.InsightsFilters {
	q := r.URL.Query()
	var filters engine.InsightsFilters

	// Tenant is only honored for admin scopes; resolveTenant() collapses
	// any non-admin attempt back to the caller's own tenant.
	filters.Tenant = q.Get("tenant")
	if v := q.Get("start"); v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			filters.Start = &ts
		}
	}
	if v := q.Get("end"); v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			filters.End = &ts
		}
	}
	if v := q.Get("group_by"); v != "" {
		filters.GroupBy = v
	}
	if v := q.Get("search"); v != "" {
		filters.Search = &v
	}
	if v := q.Get("severity"); v != "" {
		filters.Severity = &v
	}
	if v := q.Get("limit"); v != "" {
		if limit, err := strconv.Atoi(v); err == nil {
			filters.Limit = &limit
		}
	}

	return filters
}

// handleTenants is an admin-only view of all active tenants.
func (s *Server) handleTenants(w http.ResponseWriter, r *http.Request) {
	_, id, ok := scopedContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	if !id.Admin {
		writeError(w, http.StatusForbidden, "admin identity required")
		return
	}
	writeJSON(w, s.engine.TenantInfos())
}

// handleRejections is an admin-only observability endpoint for the denial
// ledger: every rejected export is visible here and in the stderr log.
func (s *Server) handleRejections(w http.ResponseWriter, r *http.Request) {
	_, id, ok := scopedContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	if !id.Admin {
		writeError(w, http.StatusForbidden, "admin identity required")
		return
	}
	if s.rejects == nil {
		writeJSON(w, map[string]string{"error": "rejection log unavailable"})
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	writeJSON(w, s.rejects.Snapshot(limit))
}

func (s *Server) handleReleases(w http.ResponseWriter, _ *http.Request) {
	var rels interface{}
	if s.relFetcher != nil {
		rels = s.relFetcher.GetReleases()
	}
	writeJSON(w, map[string]interface{}{
		"version":  s.version,
		"releases": rels,
	})
}
