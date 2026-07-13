package securepath

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestOpenPrivateRootRejectsNestedSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("Mkdir() target: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink(): %v", err)
	}

	root, err := OpenPrivateRoot(filepath.Join(link, "nested"))
	if err == nil {
		_ = root.Close()
		t.Fatal("OpenPrivateRoot() accepted a nested symlink")
	}
}

func TestOpenPrivateRootRejectsUnsafeFinalPermissions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatalf("Mkdir(): %v", err)
	}

	root, err := OpenPrivateRoot(directory)
	if err == nil {
		_ = root.Close()
		t.Fatal("OpenPrivateRoot() accepted unsafe final permissions")
	}
}

func TestOpenPrivateRootSupportsConcurrentInitialization(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "nested", "private")
	start := make(chan struct{})
	errorsChannel := make(chan error, 32)
	var waitGroup sync.WaitGroup
	for range 32 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			root, err := OpenPrivateRoot(directory)
			if err != nil {
				errorsChannel <- err
				return
			}
			_ = root.Close()
		}()
	}
	close(start)
	waitGroup.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Errorf("OpenPrivateRoot() concurrent initialization: %v", err)
	}
}

func TestOpenPrivateRootRemainsAnchoredAfterPathReplacement(t *testing.T) {
	base := t.TempDir()
	directory := filepath.Join(base, "private")
	root, err := OpenPrivateRoot(directory)
	if err != nil {
		t.Fatalf("OpenPrivateRoot(): %v", err)
	}
	defer root.Close()

	openedInfo, err := root.Stat(".")
	if err != nil {
		t.Fatalf("root.Stat(.): %v", err)
	}
	if !openedInfo.IsDir() || openedInfo.Mode().Perm() != 0o700 {
		t.Fatalf("opened root mode = %v, want private directory", openedInfo.Mode())
	}

	moved := filepath.Join(base, "moved")
	if err := os.Rename(directory, moved); err != nil {
		t.Fatalf("Rename() private directory: %v", err)
	}
	attacker := filepath.Join(base, "attacker")
	if err := os.Mkdir(attacker, 0o700); err != nil {
		t.Fatalf("Mkdir() attacker directory: %v", err)
	}
	if err := os.Symlink(attacker, directory); err != nil {
		t.Fatalf("Symlink() replacement: %v", err)
	}

	if err := root.WriteFile("anchored", []byte("safe"), 0o600); err != nil {
		t.Fatalf("root.WriteFile(): %v", err)
	}
	if _, err := os.Stat(filepath.Join(moved, "anchored")); err != nil {
		t.Fatalf("anchored file was not written to original directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(attacker, "anchored")); !os.IsNotExist(err) {
		t.Fatalf("replacement directory received anchored write: %v", err)
	}
}
