package securepath

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var ErrUnsafeDirectory = errors.New("directory path is unsafe")

func EnsurePrivateDirectory(directory string) error {
	canonical, trustedPrefix, err := canonicalizeTrustedPrefix(directory)
	if err != nil {
		return ErrUnsafeDirectory
	}
	if err := createWithoutSymlinks(canonical, trustedPrefix); err != nil {
		return ErrUnsafeDirectory
	}
	info, err := os.Lstat(canonical)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return ErrUnsafeDirectory
	}
	return nil
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

func createWithoutSymlinks(directory, trustedPrefix string) error {
	relative, err := filepath.Rel(trustedPrefix, directory)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ErrUnsafeDirectory
	}
	current := trustedPrefix
	if relative == "." {
		return nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrUnsafeDirectory
		}
	}
	return nil
}
