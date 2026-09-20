package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/control-theory/gonzo/internal/engine"
	"github.com/control-theory/gonzo/internal/releases"
	"github.com/control-theory/gonzo/internal/security"
)

// Server is the HTTP server for the Gonzo web dashboard.
type Server struct {
	engine     *engine.Engine
	httpServer *http.Server
	hub        *Hub
	staticFS   fs.FS // embedded React build assets (nil if not embedded)
	version    string
	relFetcher *releases.Fetcher

	// auth is nil in single-user local-console mode: loopback callers are
	// given the local admin scope. In multi-tenant mode it authenticates
	// every /api and /ws request (mTLS/OIDC/API token).
	auth    *security.Authenticator
	rejects *security.RejectLogger
}

// NewServer creates a new web dashboard server.
func NewServer(
	eng *engine.Engine,
	staticFS fs.FS,
	version string,
	relFetcher *releases.Fetcher,
	auth *security.Authenticator,
	rejects *security.RejectLogger,
) *Server {
	return &Server{
		engine:     eng,
		hub:        NewHub(),
		staticFS:   staticFS,
		version:    version,
		relFetcher: relFetcher,
		auth:       auth,
		rejects:    rejects,
	}
}

// Start starts the web server on the given port.
func (s *Server) Start(ctx context.Context, port int) error {
	// Start WebSocket hub
	go s.hub.Run(ctx)

	// Start broadcasting engine updates to WebSocket clients
	go s.broadcastUpdates(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.buildHandler(ctx),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	errChan := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	select {
	case err := <-errChan:
		return fmt.Errorf("web server failed to start: %w", err)
	case <-time.After(100 * time.Millisecond):
		// Started successfully
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(shutdownCtx)
	}()

	return nil
}

// buildHandler wires the authenticated API/WS surface and static assets.
// Extracted from Start so tests can exercise the full middleware chain
// over httptest without binding a fixed port.
func (s *Server) buildHandler(ctx context.Context) http.Handler {
	// API surface: method-routed sub-mux. It is mounted behind the
	// authentication chain so an unauthenticated caller cannot even reach
	// a handler.
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("GET /api/status", s.handleStatus)
	apiMux.HandleFunc("GET /api/severity", s.handleSeverity)
	apiMux.HandleFunc("GET /api/sentiment", s.handleSentiment)
	apiMux.HandleFunc("GET /api/patterns", s.handlePatterns)
	apiMux.HandleFunc("GET /api/classes", s.handleClasses)
	apiMux.HandleFunc("GET /api/logs", s.handleLogs)
	apiMux.HandleFunc("GET /api/heatmap", s.handleHeatmap)
	apiMux.HandleFunc("GET /api/anomalies", s.handleAnomalies)
	apiMux.HandleFunc("GET /api/streams", s.handleStreams)
	apiMux.HandleFunc("POST /api/summary", s.handleSummary)
	apiMux.HandleFunc("GET /api/insights-params", s.handleInsightsParams)
	apiMux.HandleFunc("GET /api/severity-history", s.handleSeverityTimeSeries)
	apiMux.HandleFunc("GET /api/top-attributes", s.handleTopAttributes)
	apiMux.HandleFunc("GET /api/releases", s.handleReleases)
	apiMux.HandleFunc("GET /api/tenants", s.handleTenants)
	apiMux.HandleFunc("GET /api/security/rejections", s.handleRejections)

	rootMux := http.NewServeMux()
	rootMux.Handle("/api/", s.guard(apiMux))
	rootMux.Handle("/ws", s.guard(http.HandlerFunc(s.handleWebSocket)))

	// Static assets (React app)
	if s.staticFS != nil {
		rootMux.Handle("/", spaHandler(s.staticFS))
	} else {
		rootMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<!DOCTYPE html><html><body>
<h1>Gonzo</h1>
<p>Web dashboard assets not embedded. Run <code>make build</code> to include them.</p>
<p>API available at <code>/api/*</code></p>
</body></html>`)
		})
	}
	return corsMiddleware(rootMux)
}

// guard wraps the protected surface. With a configured authenticator,
// credentials are verified and failures get 401/403 (or are admitted to the
// observe tenant in observe mode). Without one (local CLI), only loopback
// peers are admitted and receive the local-console admin scope.
func (s *Server) guard(next http.Handler) http.Handler {
	if s.auth != nil {
		return wsTokenAdapter(s.auth.HTTPMiddleware("web", next))
	}
	return wsTokenAdapter(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopback(r.RemoteAddr) {
			writeError(w, http.StatusForbidden, "dashboard is bound to loopback; configure authentication for remote access")
			return
		}
		id := &security.Identity{
			Tenant: engine.LocalTenant,
			Source: "local-console",
			Method: "local-loopback",
			Admin:  true,
		}
		ctx := security.ContextWithIdentity(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	}))
}

// wsTokenAdapter lets browser WebSocket clients pass credentials as
// ?token=... since browsers cannot set Authorization on the upgrade request.
func wsTokenAdapter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" && r.Header.Get("X-API-Key") == "" {
			if tok := r.URL.Query().Get("token"); tok != "" {
				r.Header.Set("Authorization", "Bearer "+tok)
			} else if tok := r.URL.Query().Get("api_key"); tok != "" {
				r.Header.Set("X-API-Key", tok)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	switch host {
	case "127.0.0.1", "::1", "localhost", "[::1]":
		return true
	}
	return false
}

// scopedContext converts the authenticated identity stamped by the guard
// into the engine scope that enforces tenant isolation.
func scopedContext(r *http.Request) (context.Context, *security.Identity, bool) {
	id, ok := security.IdentityFromContext(r.Context())
	if !ok {
		return r.Context(), nil, false
	}
	scope := engine.Scope{Tenant: id.Tenant, Admin: id.Admin}
	return engine.ContextWithScope(r.Context(), scope), id, true
}

// broadcastUpdates periodically sends per-tenant engine state updates to
// the WebSocket clients subscribed to that tenant. A client never receives
// another tenant's counters.
func (s *Server) broadcastUpdates(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	lastLogCount := make(map[string]int)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, tenant := range s.engine.ActiveTenants() {
				stats := s.engine.StatsFor(tenant)
				if lastLogCount[tenant] == stats.TotalLogsEver {
					continue // No new data for this tenant
				}
				lastLogCount[tenant] = stats.TotalLogsEver

				update := map[string]interface{}{
					"type":         "update",
					"tenant":       tenant,
					"total_logs":   stats.TotalLogsEver,
					"buffer_used":  stats.BufferUsed,
					"buffer_bytes": stats.BufferBytes,
				}

				data, err := json.Marshal(update)
				if err != nil {
					continue
				}
				s.hub.Broadcast(tenant, data)
			}
		}
	}
}

// spaHandler serves static files and falls back to index.html for SPA routing.
func spaHandler(staticFS fs.FS) http.Handler {
	fileServer := http.FileServerFS(staticFS)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to serve the file directly
		path := r.URL.Path
		if path == "/" {
			path = "index.html"
		} else if path[0] == '/' {
			path = path[1:]
		}

		// Check if file exists
		if _, err := fs.Stat(staticFS, path); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}

		// SPA fallback — serve index.html
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Error writing JSON response: %v", err)
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
