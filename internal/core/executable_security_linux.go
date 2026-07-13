//go:build linux

package core

import (
	"errors"

	"golang.org/x/sys/unix"
)

type getXattrFunc func(string, string, []byte) (int, error)

func inspectExecutableCapabilities(path string) error {
	return inspectExecutableCapabilitiesWith(path, unix.Lgetxattr)
}

func inspectExecutableCapabilitiesWith(path string, getXattr getXattrFunc) error {
	size, err := getXattr(path, "security.capability", nil)
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
		return nil
	}
	if err != nil || size != 0 {
		return ErrInvalidExecutable
	}
	return nil
}
