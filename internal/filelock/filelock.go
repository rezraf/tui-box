package filelock

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

var ErrInvalidLockFile = errors.New("lock file is invalid")

type Lock struct {
	file *os.File
}

func Acquire(path string) (*Lock, error) {
	file, created, err := open(path)
	if err != nil {
		return nil, err
	}
	removeOnError := created
	defer func() {
		if removeOnError {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()

	if created {
		if err := file.Chmod(0o600); err != nil {
			return nil, err
		}
	}
	if err := validate(path, file); err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		return nil, err
	}
	if err := validate(path, file); err != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		return nil, err
	}

	removeOnError = false
	return &Lock{file: file}, nil
}

func (lock *Lock) Close() error {
	unlockErr := unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	closeErr := lock.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func open(path string) (*os.File, bool, error) {
	flags := unix.O_CREAT | unix.O_EXCL | unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	fileDescriptor, err := unix.Open(path, flags, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fileDescriptor, err = unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, false, err
	}
	return os.NewFile(uintptr(fileDescriptor), path), created, nil
}

func validate(path string, file *os.File) error {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0o600 || !os.SameFile(pathInfo, fileInfo) {
		return ErrInvalidLockFile
	}
	return nil
}
