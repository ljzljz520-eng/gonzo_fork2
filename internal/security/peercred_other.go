//go:build !linux && !darwin

package security

import "net"

// peerCredentials is unavailable on this platform; the socket still
// authenticates clients through filesystem permissions on its path.
func peerCredentials(c net.Conn, socket string) LocalPeer {
	return LocalPeer{Socket: socket, UID: -1, GID: -1}
}
