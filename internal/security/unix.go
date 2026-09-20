package security

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// unixAddrPrefix marks RemoteAddr strings of connections accepted on a
// Gonzo-managed Unix domain socket. It is parseable from both net/http
// (r.RemoteAddr) and gRPC peer.Addr.String().
const unixAddrPrefix = "gonzounix://"

// LocalPeer describes a Unix socket peer authenticated by the kernel
// (SO_PEERCRED on Linux, getpeereid on macOS).
type LocalPeer struct {
	Socket string
	UID    int
	GID    int
	PID    int // Linux only; 0 elsewhere
}

// Source renders the stable identity string used as gonzo.source.
func (p LocalPeer) Source() string {
	if p.PID > 0 {
		return fmt.Sprintf("unix:uid=%d,gid=%d,pid=%d", p.UID, p.GID, p.PID)
	}
	return fmt.Sprintf("unix:uid=%d,gid=%d", p.UID, p.GID)
}

// Addr returns the synthetic net.Addr carried by the accepted connection.
func (p LocalPeer) Addr() net.Addr { return unixPeerAddr{peer: p} }

// unixPeerAddr implements net.Addr for socket-peer connections.
type unixPeerAddr struct {
	peer LocalPeer
}

func (a unixPeerAddr) Network() string { return "gonzo-unix" }
func (a unixPeerAddr) String() string {
	return fmt.Sprintf("%s%s#uid=%d&gid=%d&pid=%d",
		unixAddrPrefix, a.peer.Socket, a.peer.UID, a.peer.GID, a.peer.PID)
}

// UnixPeerFromAddr parses a peer address string and returns the LocalPeer
// when the connection arrived on the managed Unix socket.
func UnixPeerFromAddr(addr string) *LocalPeer {
	if !strings.HasPrefix(addr, unixAddrPrefix) {
		return nil
	}
	rest := strings.TrimPrefix(addr, unixAddrPrefix)
	path := rest
	query := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		path = rest[:i]
		query = rest[i+1:]
	}
	peer := LocalPeer{Socket: path, UID: -1, GID: -1}
	for kv := range strings.SplitSeq(query, "&") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			continue
		}
		switch k {
		case "uid":
			peer.UID = n
		case "gid":
			peer.GID = n
		case "pid":
			peer.PID = n
		}
	}
	return &peer
}

// IsLoopbackTCP reports whether addr is a TCP peer address on the loopback
// interface (e.g. 127.0.0.1:54321 or [::1]:54321). Synthetic Unix-socket
// peer addresses and non-TCP addresses return false.
func IsLoopbackTCP(addr string) bool {
	if strings.HasPrefix(addr, unixAddrPrefix) {
		return false
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// unixConn tags an accepted Unix socket connection with its kernel-verified
// peer identity.
type unixConn struct {
	net.Conn
	addr net.Addr
}

func (c *unixConn) RemoteAddr() net.Addr { return c.addr }

// unixListener accepts connections, resolves their peer credentials and
// wraps them so HTTP/gRPC layers can identify local peers.
type unixListener struct {
	ln     net.Listener
	socket string
}

func (l *unixListener) Accept() (net.Conn, error) {
	c, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	peer := peerCredentials(c, l.socket)
	return &unixConn{Conn: c, addr: peer.Addr()}, nil
}

func (l *unixListener) Close() error   { return l.ln.Close() }
func (l *unixListener) Addr() net.Addr { return l.ln.Addr() }

// ListenUnix creates (or replaces) a Unix domain socket at path with strict
// parent-directory and socket permissions, then returns the peer-cred
// aware listener.
func ListenUnix(path string, mode os.FileMode) (net.Listener, error) {
	if path == "" {
		return nil, fmt.Errorf("empty unix socket path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	if err := os.RemoveAll(path); err != nil {
		return nil, fmt.Errorf("stale socket removal: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	return &unixListener{ln: ln, socket: path}, nil
}
