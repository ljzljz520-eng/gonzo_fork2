//go:build darwin

package security

import (
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// macOS LOCAL_PEERCRED socket option: returns a struct xucred describing
// the connected peer (uid + group list). Direct getpeereid(2) raw syscalls
// are not viable on modern Go/arm64 macOS (Go 1.24+ routes syscalls through
// libSystem and unknown raw numbers fault), so we query the socket option
// through the supported getsockopt syscall.
const (
	solLocal      = 0 // SOL_LOCAL
	localPeerCred = 1 // LOCAL_PEERCRED
)

// peerCredentials resolves uid/primary-gid for an accepted Unix socket
// connection via LOCAL_PEERCRED. macOS does not expose the peer PID.
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
		cred := unix.Xucred{}
		size := uint32(unsafe.Sizeof(cred))
		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(solLocal),
			uintptr(localPeerCred),
			uintptr(unsafe.Pointer(&cred)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			return
		}
		peer.UID = int(cred.Uid)
		if cred.Ngroups > 0 {
			peer.GID = int(cred.Groups[0])
		}
	})
	return peer
}
