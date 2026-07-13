//go:build darwin || linux

package core

import (
	"errors"
	"os"
	"os/exec"
	"syscall"

	"github.com/rezraf/tui-box/internal/domain"
	"golang.org/x/sys/unix"
)

func configureCommand(command *exec.Cmd, operation string, request ConnectionRequest) {
	attributes := &syscall.SysProcAttr{Setpgid: true}
	if operation == commandRun && request.Mode == domain.ConnectionModeProxy {
		attributes.Credential = &syscall.Credential{
			Uid:    uint32(request.UID),
			Gid:    uint32(request.GID),
			Groups: []uint32{},
		}
	}
	command.SysProcAttr = attributes
}

func signalProcessGroup(pid int, signal syscall.Signal) error {
	err := syscall.Kill(-pid, signal)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

func openSecureConfig(path string, write bool) (*os.File, error) {
	flags := unix.O_CLOEXEC | unix.O_NOFOLLOW
	if write {
		flags |= unix.O_WRONLY
	} else {
		flags |= unix.O_RDONLY
	}
	fileDescriptor, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fileDescriptor), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrUnsafeConfigPath
	}
	return file, nil
}
