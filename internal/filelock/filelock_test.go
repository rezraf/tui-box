package filelock

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAcquireHonorsCanceledContextWhileContended(t *testing.T) {
	root := openTestRoot(t)
	first, err := Acquire(context.Background(), root, "test.lock")
	if err != nil {
		t.Fatalf("first Acquire() returned an unexpected error: %v", err)
	}
	defer first.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = Acquire(ctx, root, "test.lock")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("contended Acquire() error = %v, want context.Canceled", err)
	}
}

func TestAcquireRetriesUntilContendedLockIsReleased(t *testing.T) {
	root := openTestRoot(t)
	first, err := Acquire(context.Background(), root, "test.lock")
	if err != nil {
		t.Fatalf("first Acquire() returned an unexpected error: %v", err)
	}
	go func() {
		time.Sleep(25 * time.Millisecond)
		_ = first.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	second, err := Acquire(ctx, root, "test.lock")
	if err != nil {
		t.Fatalf("retrying Acquire() returned an unexpected error: %v", err)
	}
	defer second.Close()
}

func TestAcquireHonorsDeadlineWhileContended(t *testing.T) {
	root := openTestRoot(t)
	first, err := Acquire(context.Background(), root, "test.lock")
	if err != nil {
		t.Fatalf("first Acquire() returned an unexpected error: %v", err)
	}
	defer first.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err = Acquire(ctx, root, "test.lock")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended Acquire() error = %v, want context.DeadlineExceeded", err)
	}
}

func TestAcquireClosesDescriptorsOnValidationFailure(t *testing.T) {
	root := openTestRoot(t)
	file, err := root.OpenFile("invalid.lock", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("OpenFile() invalid lock: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close() invalid lock: %v", err)
	}

	assertFailedAcquiresDoNotLeakDescriptors(t, func() error {
		_, err := Acquire(context.Background(), root, "invalid.lock")
		if !errors.Is(err, ErrInvalidLockFile) {
			t.Fatalf("Acquire() error = %v, want ErrInvalidLockFile", err)
		}
		return err
	})
}

func TestAcquireClosesDescriptorsOnCancellation(t *testing.T) {
	root := openTestRoot(t)
	first, err := Acquire(context.Background(), root, "test.lock")
	if err != nil {
		t.Fatalf("first Acquire() returned an unexpected error: %v", err)
	}
	defer first.Close()

	assertFailedAcquiresDoNotLeakDescriptors(t, func() error {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := Acquire(ctx, root, "test.lock")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Acquire() error = %v, want context.Canceled", err)
		}
		return err
	})
}

func TestAcquireContendsAcrossProcesses(t *testing.T) {
	if os.Getenv("TUIBOX_FILELOCK_HELPER") == "1" {
		runFileLockHelper(t)
		return
	}

	directory := t.TempDir()
	readyPath := filepath.Join(directory, "ready")
	command := exec.Command(os.Args[0], "-test.run=^TestAcquireContendsAcrossProcesses$")
	command.Env = append(os.Environ(),
		"TUIBOX_FILELOCK_HELPER=1",
		"TUIBOX_FILELOCK_DIRECTORY="+directory,
	)
	if err := command.Start(); err != nil {
		t.Fatalf("start helper process: %v", err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper process did not acquire the lock")
		}
		time.Sleep(10 * time.Millisecond)
	}

	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("OpenRoot(): %v", err)
	}
	defer root.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err = Acquire(ctx, root, "process.lock")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire() error = %v, want subprocess contention deadline", err)
	}
}

func runFileLockHelper(t *testing.T) {
	directory := os.Getenv("TUIBOX_FILELOCK_DIRECTORY")
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("helper OpenRoot(): %v", err)
	}
	defer root.Close()
	lock, err := Acquire(context.Background(), root, "process.lock")
	if err != nil {
		t.Fatalf("helper Acquire(): %v", err)
	}
	defer lock.Close()
	if err := root.WriteFile("ready", []byte("ready"), 0o600); err != nil {
		t.Fatalf("helper WriteFile(): %v", err)
	}
	time.Sleep(10 * time.Second)
}

func openTestRoot(t *testing.T) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatalf("OpenRoot(): %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func assertFailedAcquiresDoNotLeakDescriptors(t *testing.T, acquire func() error) {
	t.Helper()
	runtime.GC()
	before := countOpenDescriptors()
	for range 100 {
		if err := acquire(); err == nil {
			t.Fatal("failed Acquire() returned nil error")
		}
	}
	runtime.GC()
	after := countOpenDescriptors()
	if after > before+2 {
		t.Fatalf("open descriptors grew from %d to %d after failed Acquire() calls", before, after)
	}
}

func countOpenDescriptors() int {
	count := 0
	for descriptor := 0; descriptor < 1024; descriptor++ {
		if _, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0); err == nil {
			count++
		}
	}
	return count
}
