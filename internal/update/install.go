package update

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rezraf/tui-box/internal/app"
)

const (
	helperBinaryName      = "tuibox-update-helper"
	internalApplyArgument = "--internal-apply-update"
	recoveryMarkerSuffix  = ".recovery"
	sudoPath              = "/usr/bin/sudo"
)

const InternalApplyArgument = internalApplyArgument

type installationLayout struct {
	Client string
	Daemon string
	Helper string
}

type fileOperations struct {
	rename        func(string, string) error
	remove        func(string) error
	syncDirectory func(string) error
}

type fileSnapshot struct {
	info   os.FileInfo
	mode   os.FileMode
	uid    uint32
	gid    uint32
	digest [sha256.Size]byte
}

type preparedReplacement struct {
	target         string
	staged         string
	backup         string
	targetSnapshot fileSnapshot
	stagedSnapshot fileSnapshot
	installed      bool
	backedUp       bool
}

func (updater *Updater) Apply(ctx context.Context, info app.UpdateInfo) error {
	if !updater.validApplyRequest(info) {
		return ErrInvalidUpdate
	}
	clientPath, err := updater.executablePath()
	if err != nil {
		return ErrInvalidInstallation
	}
	helperPath, err := helperPathFromClient(clientPath)
	if err != nil || updater.validateHelper(helperPath) != nil {
		return ErrInvalidInstallation
	}
	helperSnapshot, err := captureFileSnapshot(helperPath)
	if err != nil {
		return ErrInvalidInstallation
	}
	args := []string{"--", helperPath, internalApplyArgument, canonicalVersion(info.LatestVersion)}
	if updater.validateHelper(helperPath) != nil || helperSnapshot.validate(helperPath) != nil {
		return ErrInvalidInstallation
	}
	if err := updater.runCommand(ctx, sudoPath, args, updater.stdin, updater.stdout, updater.stderr); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return ErrReplaceFailed
	}
	return nil
}

func (updater *Updater) validApplyRequest(info app.UpdateInfo) bool {
	if !info.Available || canonicalVersion(info.CurrentVersion) != canonicalVersion(updater.currentVersion) {
		return false
	}
	comparison, ok := compareStableVersions(info.CurrentVersion, info.LatestVersion)
	return ok && comparison < 0
}

func helperPathFromClient(clientPath string) (string, error) {
	clean, err := cleanAbsolutePath(clientPath)
	if err != nil || filepath.Base(clean) != "tuibox" {
		return "", ErrInvalidInstallation
	}
	parent := filepath.Dir(clean)
	if filepath.Base(parent) == "bin" {
		prefix := filepath.Dir(parent)
		return filepath.Join(prefix, "libexec", "tuibox", helperBinaryName), nil
	}
	if filepath.Base(parent) == "tuibox" && filepath.Base(filepath.Dir(parent)) == "libexec" {
		return filepath.Join(parent, helperBinaryName), nil
	}
	return "", ErrInvalidInstallation
}

func layoutFromHelper(helperPath string) (installationLayout, error) {
	clean, err := cleanAbsolutePath(helperPath)
	if err != nil || filepath.Base(clean) != helperBinaryName {
		return installationLayout{}, ErrInvalidInstallation
	}
	directory := filepath.Dir(clean)
	if filepath.Base(directory) != "tuibox" || filepath.Base(filepath.Dir(directory)) != "libexec" {
		return installationLayout{}, ErrInvalidInstallation
	}
	return installationLayout{
		Client: filepath.Join(directory, "tuibox"),
		Daemon: filepath.Join(directory, "tuiboxd"),
		Helper: clean,
	}, nil
}

func cleanAbsolutePath(value string) (string, error) {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsAny(value, "\x00\r\n") {
		return "", ErrInvalidInstallation
	}
	return value, nil
}

func regularExecutable(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

func captureFileSnapshot(path string) (fileSnapshot, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return fileSnapshot{}, ErrInvalidInstallation
	}
	file, err := os.Open(path)
	if err != nil {
		return fileSnapshot{}, ErrInvalidInstallation
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return fileSnapshot{}, ErrInvalidInstallation
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fileSnapshot{}, ErrInvalidInstallation
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) {
		return fileSnapshot{}, ErrInvalidInstallation
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok {
		return fileSnapshot{}, ErrInvalidInstallation
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return fileSnapshot{info: opened, mode: opened.Mode(), uid: stat.Uid, gid: stat.Gid, digest: digest}, nil
}

func (snapshot fileSnapshot) validate(path string) error {
	current, err := captureFileSnapshot(path)
	if err != nil || !os.SameFile(snapshot.info, current.info) || snapshot.mode != current.mode || snapshot.uid != current.uid || snapshot.gid != current.gid || snapshot.digest != current.digest {
		return ErrInvalidInstallation
	}
	return nil
}

func validatePrivilegeHelper(path string) error {
	return validatePrivilegeHelperForOwner(path, 0)
}

func validatePrivilegeHelperForOwner(path string, ownerUID uint32) error {
	if filepath.Base(path) != helperBinaryName || trustedParentChain(filepath.Dir(path), string(filepath.Separator), ownerUID) != nil {
		return ErrInvalidInstallation
	}
	if ownerOwnedSecure(path, false, ownerUID) != nil || !regularExecutable(path) {
		return ErrInvalidInstallation
	}
	return nil
}

func defaultExecutablePath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", ErrInvalidInstallation
	}
	return filepath.EvalSymlinks(path)
}

func defaultCommandRunner(ctx context.Context, path string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, path, args...)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

func ApplyInstalled(ctx context.Context, config Config, version, helperPath string, effectiveUID int) error {
	if effectiveUID != 0 || canonicalVersion(version) == "" {
		return ErrInvalidInstallation
	}
	layout, err := layoutFromHelper(helperPath)
	if err != nil || validatePrivilegedLayout(layout) != nil {
		return ErrInvalidInstallation
	}
	updater, err := New(config)
	if err != nil {
		return err
	}
	return updater.applyPrivilegedValidated(ctx, version, layout, fileOperations{}, func() error {
		return validatePrivilegedLayout(layout)
	})
}

func (updater *Updater) applyPrivileged(ctx context.Context, version string, layout installationLayout, operations fileOperations) error {
	return updater.applyPrivilegedValidated(ctx, version, layout, operations, nil)
}

func (updater *Updater) applyPrivilegedValidated(ctx context.Context, version string, layout installationLayout, operations fileOperations, revalidate func() error) error {
	comparison, ok := compareStableVersions(updater.currentVersion, version)
	if !ok || comparison >= 0 {
		return ErrInvalidUpdate
	}
	releases, err := updater.fetchReleases(ctx)
	if err != nil {
		return err
	}
	selected, found := findStableRelease(releases, version)
	if !found {
		return ErrReleaseUnavailable
	}
	archive, err := updater.downloadRelease(ctx, selected)
	if err != nil {
		return err
	}
	payload, err := extractBinaries(archive)
	if err != nil {
		return err
	}
	if revalidate != nil && revalidate() != nil {
		return ErrInvalidInstallation
	}
	return replaceInstallation(layout, payload, operations)
}

func validatePrivilegedLayout(layout installationLayout) error {
	return validatePrivilegedLayoutForOwner(layout, 0)
}

func validatePrivilegedLayoutForOwner(layout installationLayout, ownerUID uint32) error {
	directory := filepath.Dir(layout.Helper)
	if err := trustedParentChain(directory, string(filepath.Separator), ownerUID); err != nil {
		return err
	}
	if err := ownerOwnedSecure(directory, true, ownerUID); err != nil {
		return err
	}
	for _, path := range []string{layout.Client, layout.Daemon, layout.Helper} {
		if filepath.Dir(path) != directory || ownerOwnedSecure(path, false, ownerUID) != nil {
			return ErrInvalidInstallation
		}
	}
	return nil
}

func trustedParentChain(path, trustedRoot string, allowedUID uint32) error {
	clean, err := cleanAbsolutePath(path)
	if err != nil {
		return ErrInvalidInstallation
	}
	root, err := cleanAbsolutePath(trustedRoot)
	if err != nil || root != string(filepath.Separator) && clean != root && !strings.HasPrefix(clean, root+string(filepath.Separator)) {
		return ErrInvalidInstallation
	}
	for current := clean; ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return ErrInvalidInstallation
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && stat.Uid != allowedUID || validatePathACL(current) != nil {
			return ErrInvalidInstallation
		}
		if current == root {
			return nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return ErrInvalidInstallation
		}
	}
}

func rootOwnedSecure(path string, directory bool) error {
	return ownerOwnedSecure(path, directory, 0)
}

func ownerOwnedSecure(path string, directory bool, ownerUID uint32) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return ErrInvalidInstallation
	}
	if directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return ErrInvalidInstallation
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || validatePathACL(path) != nil {
		return ErrInvalidInstallation
	}
	return nil
}

func replaceInstallation(layout installationLayout, payload binariesPayload, operations fileOperations) error {
	operations = defaultFileOperations(operations)
	replacements, err := prepareReplacements(layout, payload)
	if err != nil {
		return ErrReplaceFailed
	}
	if err := installReplacements(replacements, operations); err != nil {
		incomplete := rollbackReplacements(replacements, operations)
		cleanupStagedReplacements(replacements, operations)
		if incomplete {
			return errors.Join(ErrReplaceFailed, ErrRollbackIncomplete)
		}
		return ErrReplaceFailed
	}
	cleanupCommittedReplacements(replacements, operations)
	return nil
}

func prepareReplacements(layout installationLayout, payload binariesPayload) ([]*preparedReplacement, error) {
	items := []struct {
		target string
		data   []byte
	}{
		{target: layout.Daemon, data: payload.Daemon},
		{target: layout.Client, data: payload.Client},
		{target: layout.Helper, data: payload.Client},
	}
	replacements := make([]*preparedReplacement, 0, len(items))
	for _, item := range items {
		replacement, err := prepareReplacement(item.target, item.data)
		if err != nil {
			cleanupStagedReplacements(replacements, defaultFileOperations(fileOperations{}))
			return nil, err
		}
		replacements = append(replacements, replacement)
	}
	return replacements, nil
}

func prepareReplacement(target string, data []byte) (*preparedReplacement, error) {
	if len(data) == 0 || len(data) > maxBinaryBytes || !regularExecutable(target) {
		return nil, ErrReplaceFailed
	}
	targetSnapshot, err := captureFileSnapshot(target)
	if err != nil {
		return nil, ErrReplaceFailed
	}
	directory := filepath.Dir(target)
	staged, err := writeTemporaryExecutable(directory, "."+filepath.Base(target)+".new-", data)
	if err != nil {
		return nil, err
	}
	stagedSnapshot, err := captureFileSnapshot(staged)
	if err != nil {
		_ = os.Remove(staged)
		return nil, ErrReplaceFailed
	}
	backup, err := reserveTemporaryName(directory, "."+filepath.Base(target)+".backup-")
	if err != nil {
		_ = os.Remove(staged)
		return nil, err
	}
	return &preparedReplacement{target: target, staged: staged, backup: backup, targetSnapshot: targetSnapshot, stagedSnapshot: stagedSnapshot}, nil
}

func writeTemporaryExecutable(directory, pattern string, data []byte) (string, error) {
	file, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return "", err
	}
	path := file.Name()
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()
	if err := file.Chmod(0o755); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if _, err := file.Write(data); err != nil || file.Sync() != nil || file.Close() != nil {
		file = nil
		_ = os.Remove(path)
		return "", ErrReplaceFailed
	}
	file = nil
	if stripPathACL(path) != nil || os.Chmod(path, 0o755) != nil || validatePathACL(path) != nil {
		_ = os.Remove(path)
		return "", ErrReplaceFailed
	}
	return path, nil
}

func reserveTemporaryName(directory, pattern string) (string, error) {
	file, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return "", err
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}
	return path, nil
}

func installReplacements(replacements []*preparedReplacement, operations fileOperations) error {
	for _, replacement := range replacements {
		if replacement.targetSnapshot.validate(replacement.target) != nil || validatePathACL(replacement.target) != nil ||
			replacement.stagedSnapshot.validate(replacement.staged) != nil || validatePathACL(replacement.staged) != nil {
			return ErrReplaceFailed
		}
		if err := operations.rename(replacement.target, replacement.backup); err != nil {
			return err
		}
		replacement.backedUp = true
		if err := syncReplacementDirectory(replacement, operations); err != nil {
			return err
		}
		if replacement.targetSnapshot.validate(replacement.backup) != nil {
			return ErrReplaceFailed
		}
		if err := operations.rename(replacement.staged, replacement.target); err != nil {
			return err
		}
		replacement.installed = true
		if err := syncReplacementDirectory(replacement, operations); err != nil {
			return err
		}
		if replacement.stagedSnapshot.validate(replacement.target) != nil || validatePathACL(replacement.target) != nil {
			return ErrReplaceFailed
		}
	}
	return nil
}

func rollbackReplacements(replacements []*preparedReplacement, operations fileOperations) bool {
	incomplete := false
	for index := len(replacements) - 1; index >= 0; index-- {
		replacement := replacements[index]
		if !replacement.backedUp {
			continue
		}
		if replacement.installed {
			_ = operations.remove(replacement.target)
		}
		if restoreReplacement(replacement, operations) != nil {
			incomplete = true
			preserveRecoveryBackup(replacement, operations)
		}
	}
	return incomplete
}

func restoreReplacement(replacement *preparedReplacement, operations fileOperations) error {
	if err := operations.rename(replacement.backup, replacement.target); err != nil {
		return err
	}
	replacement.backedUp = false
	replacement.installed = false
	if err := syncReplacementDirectory(replacement, operations); err != nil {
		return err
	}
	if replacement.targetSnapshot.validate(replacement.target) != nil || validatePathACL(replacement.target) != nil {
		return ErrRollbackIncomplete
	}
	return nil
}

func preserveRecoveryBackup(replacement *preparedReplacement, operations fileOperations) {
	if !replacement.backedUp {
		return
	}
	_ = writeRecoveryMarker(replacement.backup+recoveryMarkerSuffix, replacement.target)
	_ = syncReplacementDirectory(replacement, operations)
}

func writeRecoveryMarker(path, target string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(file, filepath.Base(target)+"\n"); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func cleanupStagedReplacements(replacements []*preparedReplacement, operations fileOperations) {
	for _, replacement := range replacements {
		_ = operations.remove(replacement.staged)
	}
}

func cleanupCommittedReplacements(replacements []*preparedReplacement, operations fileOperations) {
	cleanupStagedReplacements(replacements, operations)
	for _, replacement := range replacements {
		if !replacement.backedUp || operations.remove(replacement.backup) != nil {
			continue
		}
		replacement.backedUp = false
		_ = syncReplacementDirectory(replacement, operations)
	}
}

func syncReplacementDirectory(replacement *preparedReplacement, operations fileOperations) error {
	return operations.syncDirectory(filepath.Dir(replacement.target))
}

func defaultFileOperations(operations fileOperations) fileOperations {
	if operations.rename == nil {
		operations.rename = os.Rename
	}
	if operations.remove == nil {
		operations.remove = os.Remove
	}
	if operations.syncDirectory == nil {
		operations.syncDirectory = syncDirectory
	}
	return operations
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}
