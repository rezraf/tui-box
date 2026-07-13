//go:build darwin

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
	var credentials *unix.Xucred
	var credentialErr error
	if err := raw.Control(func(descriptor uintptr) {
		credentials, credentialErr = unix.GetsockoptXucred(int(descriptor), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil || credentialErr != nil || credentials == nil || credentials.Ngroups < 1 {
		return PeerCredentials{}, ErrAccessDenied
	}
	return PeerCredentials{UID: int(credentials.Uid), GID: int(credentials.Groups[0])}, nil
}
