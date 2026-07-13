//go:build darwin

package update

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
)

const maxACLInspectionBytes = 64 << 10

func validatePathACL(path string) error {
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidInstallation
	}
	command := exec.Command("/bin/ls", "-lde", "--", path)
	command.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	var output bytes.Buffer
	stdout := &limitedBuffer{buffer: &output, remaining: maxACLInspectionBytes}
	stderr := &limitedBuffer{buffer: &output, remaining: maxACLInspectionBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil || stdout.exceeded || stderr.exceeded {
		return ErrInvalidInstallation
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return ErrInvalidInstallation
	}
	for _, line := range strings.Split(output.String(), "\n")[1:] {
		entry := strings.TrimSpace(line)
		allowIndex := strings.Index(entry, " allow ")
		if allowIndex < 0 {
			continue
		}
		principal := entry[:allowIndex]
		if space := strings.IndexByte(principal, ' '); space >= 0 {
			principal = principal[space+1:]
		}
		if principal == "user:root" {
			continue
		}
		for _, permission := range strings.Split(entry[allowIndex+len(" allow "):], ",") {
			switch strings.TrimSpace(permission) {
			case "write", "append", "delete", "delete_child", "add_file", "add_subdirectory", "writeattr", "writeextattr", "writesecurity", "chown":
				return ErrInvalidInstallation
			}
		}
	}
	return nil
}

func stripPathACL(path string) error {
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 {
		return ErrReplaceFailed
	}
	command := exec.Command("/bin/chmod", "-N", path)
	command.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	if err := command.Run(); err != nil {
		return ErrReplaceFailed
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || validatePathACL(path) != nil {
		return ErrReplaceFailed
	}
	return nil
}

type limitedBuffer struct {
	buffer    *bytes.Buffer
	remaining int
	exceeded  bool
}

func (writer *limitedBuffer) Write(data []byte) (int, error) {
	original := len(data)
	if len(data) > writer.remaining {
		data = data[:writer.remaining]
		writer.exceeded = true
	}
	if len(data) > 0 {
		_, _ = writer.buffer.Write(data)
		writer.remaining -= len(data)
	}
	if writer.exceeded {
		return original, nil
	}
	return original, nil
}
