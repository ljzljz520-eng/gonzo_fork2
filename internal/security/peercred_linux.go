//go:build linux

package security

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerCredentials resolves SO_PEERCRED (uid/gid/pid) for an accepted Unix
// socket connection.
func peerCredentials(c net.Conn, socket string) LocalPeer {
	peer := LocalPeer{Socket: socket, UID: -1, GID: -1}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return peer
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return peer
	}
	_ = raw.Control(func(fd uintptr) {
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			return
		}
		peer.UID = int(ucred.Uid)
		peer.GID = int(ucred.Gid)
		peer.PID = int(ucred.Pid)
	})
	return peer
}
