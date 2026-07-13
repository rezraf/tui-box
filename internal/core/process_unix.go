//go:build darwin || linux

package core

import (
	"errors"
	"os"
	"os/exec"
	"syscall"

	"github.com/rezraf/tui-box/internal/domain"
)

func configureCommand(command *exec.Cmd, operation string, request ConnectionRequest) {
	attributes := &syscall.SysProcAttr{Setpgid: true}
	if operation == commandRun && request.Mode == domain.ConnectionModeProxy &&
		(request.UID != os.Geteuid() || request.GID != os.Getegid()) {
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

func fileIdentity(info os.FileInfo) (int, int, bool) {
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(status.Uid), int(status.Gid), true
}

func fileOwnerID(info os.FileInfo) (int, bool) {
	uid, _, ok := fileIdentity(info)
	return uid, ok
}
