package web

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/control-theory/gonzo/internal/security"
	"nhooyr.io/websocket"
)

// Hub manages tenant-partitioned WebSocket client connections. A client
// only ever receives broadcasts for the tenant its identity is scoped to.
type Hub struct {
	mu      sync.RWMutex
	clients map[string]map[*Client]bool
}

// Client represents a single WebSocket connection bound to one tenant.
type Client struct {
	conn   *websocket.Conn
	send   chan []byte
	tenant string
}

// NewHub creates a new WebSocket hub.
func NewHub() *Hub {
	return &Hub{
		clients: make(map[string]map[*Client]bool),
	}
}

// Run starts the hub, cleaning up closed connections.
func (h *Hub) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			h.mu.Lock()
			for tenant := range h.clients {
				for c := range h.clients[tenant] {
					close(c.send)
					delete(h.clients[tenant], c)
				}
			}
			h.mu.Unlock()
			return
		case <-ticker.C:
			// Periodic cleanup handled by write pump detecting closed conns
		}
	}
}

// Register adds a tenant-bound client to the hub.
func (h *Hub) Register(c *Client) {
	h.mu.Lock()
	if h.clients[c.tenant] == nil {
		h.clients[c.tenant] = make(map[*Client]bool)
	}
	h.clients[c.tenant][c] = true
	h.mu.Unlock()
}

// Unregister removes a client from the hub.
func (h *Hub) Unregister(c *Client) {
	h.mu.Lock()
	if set := h.clients[c.tenant]; set != nil {
		if _, ok := set[c]; ok {
			close(c.send)
			delete(set, c)
		}
		if len(set) == 0 {
			delete(h.clients, c.tenant)
		}
	}
	h.mu.Unlock()
}

// Broadcast sends a message only to clients subscribed to tenant.
func (h *Hub) Broadcast(tenant string, msg []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for c := range h.clients[tenant] {
		select {
		case c.send <- msg:
		default:
			// Client buffer full, skip
		}
	}
}

// handleWebSocket handles WebSocket upgrade and manages the connection. The
// guard has already authenticated the request; the identity pins the
// connection to a tenant for its entire lifetime.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	id, ok := security.IdentityFromContext(r.Context())
	if !ok || id == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	tenant := id.Tenant
	// Admins may subscribe to a specific tenant; non-admins are pinned.
	if requested := r.URL.Query().Get("tenant"); requested != "" && id.Admin {
		tenant = requested
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Loopback-only surface; auth handled by guard
	})
	if err != nil {
		log.Printf("WebSocket accept error: %v", err)
		return
	}

	client := &Client{
		conn:   conn,
		send:   make(chan []byte, 64),
		tenant: tenant,
	}
	s.hub.Register(client)

	ctx := r.Context()

	// Write pump
	go func() {
		defer func() {
			s.hub.Unregister(client)
			conn.Close(websocket.StatusNormalClosure, "")
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-client.send:
				if !ok {
					return
				}
				writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := conn.Write(writeCtx, websocket.MessageText, msg)
				cancel()
				if err != nil {
					return
				}
			}
		}
	}()

	// Read pump (just consume and discard — we don't expect client messages)
	for {
		_, _, err := conn.Read(ctx)
		if err != nil {
			break
		}
	}
}
