package securepath

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var ErrUnsafeDirectory = errors.New("directory path is unsafe")

func EnsurePrivateDirectory(directory string) error {
	root, err := OpenPrivateRoot(directory)
	if err != nil {
		return err
	}
	return root.Close()
}

func OpenPrivateRoot(directory string) (*os.Root, error) {
	canonical, trustedPrefix, err := canonicalizeTrustedPrefix(directory)
	if err != nil {
		return nil, ErrUnsafeDirectory
	}
	relative, err := filepath.Rel(trustedPrefix, canonical)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, ErrUnsafeDirectory
	}

	root, err := os.OpenRoot(trustedPrefix)
	if err != nil {
		return nil, ErrUnsafeDirectory
	}
	if relative != "." {
		for _, component := range strings.Split(relative, string(filepath.Separator)) {
			next, openErr := openOrCreateDirectory(root, component)
			_ = root.Close()
			if openErr != nil {
				return nil, ErrUnsafeDirectory
			}
			root = next
		}
	}
	if err := ValidatePrivateRoot(root); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}

func ValidatePrivateRoot(root *os.Root) error {
	info, err := root.Stat(".")
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return ErrUnsafeDirectory
	}
	return nil
}

func CreatePrivateTemp(root *os.Root, prefix string) (*os.File, string, error) {
	for range 100 {
		name := prefix + rand.Text()
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			_ = root.Remove(name)
			return nil, "", err
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			_ = file.Close()
			_ = root.Remove(name)
			return nil, "", ErrUnsafeDirectory
		}
		return file, name, nil
	}
	return nil, "", errors.New("could not create temporary file")
}

func SyncRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func canonicalizeTrustedPrefix(directory string) (string, string, error) {
	if directory == "" {
		return "", "", ErrUnsafeDirectory
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return "", "", err
	}
	absolute = filepath.Clean(absolute)
	components := strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator))
	if len(components) == 0 || components[0] == "" {
		return "", "", ErrUnsafeDirectory
	}

	prefix := string(filepath.Separator) + components[0]
	trustedPrefix, err := filepath.EvalSymlinks(prefix)
	if err != nil {
		return "", "", err
	}
	canonical := trustedPrefix
	for _, component := range components[1:] {
		canonical = filepath.Join(canonical, component)
	}
	return canonical, trustedPrefix, nil
}

func openOrCreateDirectory(parent *os.Root, name string) (*os.Root, error) {
	info, err := parent.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if err := parent.Mkdir(name, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		info, err = parent.Lstat(name)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, ErrUnsafeDirectory
	}

	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	openedInfo, err := child.Stat(".")
	if err != nil || !openedInfo.IsDir() || !os.SameFile(info, openedInfo) {
		_ = child.Close()
		return nil, ErrUnsafeDirectory
	}
	return child, nil
}
