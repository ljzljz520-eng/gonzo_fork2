package security

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestListenUnixPeerCredentials(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "gonzo.sock")

	ln, err := ListenUnix(sock, 0o660)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	info, err := os.Stat(sock)
	if err != nil {
		t.Fatalf("socket not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o660 {
		t.Fatalf("socket perm = %o, want 0660", perm)
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var srvConn net.Conn
	select {
	case srvConn = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("accept never returned")
	}
	t.Cleanup(func() { _ = srvConn.Close() })

	peer := UnixPeerFromAddr(srvConn.RemoteAddr().String())
	if peer == nil {
		t.Fatalf("remote addr %q did not resolve to a local peer", srvConn.RemoteAddr())
	}
	if peer.UID != os.Getuid() {
		t.Fatalf("peer uid = %d, want %d", peer.UID, os.Getuid())
	}
	if peer.GID != os.Getgid() {
		t.Fatalf("peer gid = %d, want %d", peer.GID, os.Getgid())
	}
	if peer.Source() == "" {
		t.Fatal("empty source")
	}
}

func TestIsLoopbackTCP(t *testing.T) {
	if !IsLoopbackTCP("127.0.0.1:51234") {
		t.Error("127.0.0.1 must be loopback")
	}
	if !IsLoopbackTCP("[::1]:51234") {
		t.Error("::1 must be loopback")
	}
	if IsLoopbackTCP("10.0.0.5:51234") {
		t.Error("10.0.0.5 must not be loopback")
	}
	if IsLoopbackTCP("gonzounix:///tmp/gonzo.sock#uid=1&gid=1&pid=0") {
		t.Error("unix peer address must not classify as loopback TCP")
	}
}
