//go:build linux

package rpc

import (
	"net"

	"golang.org/x/sys/unix"
)

func kernelPeerCredentials(connection *net.UnixConn) (PeerCredentials, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return PeerCredentials{}, ErrAccessDenied
	}
	var credentials *unix.Ucred
	var credentialErr error
	if err := raw.Control(func(descriptor uintptr) {
		credentials, credentialErr = unix.GetsockoptUcred(int(descriptor), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credentialErr != nil || credentials == nil {
		return PeerCredentials{}, ErrAccessDenied
	}
	return PeerCredentials{UID: int(credentials.Uid), GID: int(credentials.Gid)}, nil
}
