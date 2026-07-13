package filelock

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const retryInterval = 5 * time.Millisecond

var ErrInvalidLockFile = errors.New("lock file is invalid")

type Lock struct {
	file *os.File
}

func Acquire(ctx context.Context, root *os.Root, name string) (*Lock, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, created, err := open(root, name)
	if err != nil {
		return nil, err
	}
	acquired := false
	defer func() {
		if !acquired {
			_ = file.Close()
		}
	}()

	if created {
		if err := file.Chmod(0o600); err != nil {
			return nil, err
		}
	}
	if err := validate(root, name, file); err != nil {
		return nil, err
	}
	if err := acquire(ctx, file); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		return nil, err
	}
	if err := validate(root, name, file); err != nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		return nil, err
	}

	acquired = true
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

func open(root *os.Root, name string) (*os.File, bool, error) {
	flags := os.O_CREATE | os.O_EXCL | os.O_RDWR | unix.O_NOFOLLOW
	file, err := root.OpenFile(name, flags, 0o600)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		file, err = root.OpenFile(name, os.O_RDWR|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, false, err
	}
	return file, created, nil
}

func acquire(ctx context.Context, file *os.File) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return err
		}

		timer := time.NewTimer(retryInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func validate(root *os.Root, name string, file *os.File) error {
	pathInfo, err := root.Lstat(name)
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
