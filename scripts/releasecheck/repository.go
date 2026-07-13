package releasecheck

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func ValidateRepository(root string) (Report, error) {
	repository, err := resolveRepositoryRoot(root)
	if err != nil {
		return Report{}, err
	}
	tracked, err := loadGitSnapshot(repository, "--cached")
	if err != nil {
		return Report{}, fmt.Errorf("load tracked tree: %w", err)
	}
	candidate, err := loadGitSnapshot(repository, "--cached", "--others", "--exclude-standard")
	if err != nil {
		return Report{}, fmt.Errorf("load future source tree: %w", err)
	}
	archive, err := CreateSourceArchive(candidate)
	if err != nil {
		return Report{}, fmt.Errorf("create future source archive: %w", err)
	}
	archived, err := ReadSourceArchive(archive)
	if err != nil {
		return Report{}, fmt.Errorf("read future source archive: %w", err)
	}
	if err := EqualSnapshots(candidate, archived); err != nil {
		return Report{}, fmt.Errorf("future source archive integrity: %w", err)
	}
	findings := ScanSnapshot("tracked", tracked, false)
	findings = append(findings, ScanSnapshot("archive", archived, true)...)
	workspace, err := scanWorkspaceArtifacts(repository)
	if err != nil {
		return Report{}, err
	}
	findings = append(findings, workspace...)
	return Report{
		TrackedFiles: len(tracked),
		ArchiveFiles: len(archived),
		Findings:     deduplicateFindings(findings),
	}, nil
}

func resolveRepositoryRoot(root string) (string, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	command := exec.Command("git", "-C", absolute, "rev-parse", "--show-toplevel")
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("resolve git repository: %w", err)
	}
	topLevel := filepath.Clean(strings.TrimSpace(string(output)))
	if topLevel != filepath.Clean(absolute) {
		return "", fmt.Errorf("validator must run at repository root %s", topLevel)
	}
	return topLevel, nil
}

func loadGitSnapshot(root string, arguments ...string) (Snapshot, error) {
	paths, err := listGitFiles(root, arguments...)
	if err != nil {
		return nil, err
	}
	snapshot := make(Snapshot, len(paths))
	for _, name := range paths {
		file, err := loadRepositoryFile(root, name)
		if err != nil {
			return nil, err
		}
		snapshot[name] = file
	}
	return snapshot, nil
}

func listGitFiles(root string, arguments ...string) ([]string, error) {
	commandArguments := append([]string{"-C", root, "ls-files", "-z"}, arguments...)
	output, err := exec.Command("git", commandArguments...).Output()
	if err != nil {
		return nil, err
	}
	parts := bytes.Split(output, []byte{0})
	paths := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		name := string(part)
		if !validRepositoryPath(name) {
			return nil, fmt.Errorf("invalid git path %q", name)
		}
		paths = append(paths, name)
	}
	sort.Strings(paths)
	return paths, nil
}

func loadRepositoryFile(root, name string) (File, error) {
	fullPath := filepath.Join(root, filepath.FromSlash(name))
	info, err := os.Lstat(fullPath)
	if err != nil {
		return File{}, fmt.Errorf("stat %s: %w", name, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		target, err := os.Readlink(fullPath)
		if err != nil {
			return File{}, fmt.Errorf("read link %s: %w", name, err)
		}
		return File{Path: name, Mode: info.Mode(), Data: []byte(target)}, nil
	}
	if !info.Mode().IsRegular() {
		return File{}, fmt.Errorf("%s is not a regular file", name)
	}
	if info.Size() > maxSourceArchiveSize {
		return File{}, fmt.Errorf("%s exceeds source file load limit", name)
	}
	contents, err := os.ReadFile(fullPath)
	if err != nil {
		return File{}, fmt.Errorf("read %s: %w", name, err)
	}
	return File{Path: name, Mode: info.Mode(), Data: contents}, nil
}

func scanWorkspaceArtifacts(root string) ([]Finding, error) {
	var findings []Finding
	err := filepath.WalkDir(root, func(fullPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name, err := filepath.Rel(root, fullPath)
		if err != nil {
			return err
		}
		name = filepath.ToSlash(name)
		if name == "." {
			return nil
		}
		if name == ".git" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if privateFilePath(name) {
			findings = append(findings, newFinding("workspace", name, "private-file", "private or local-only file exists in the repository workspace"))
			if entry.IsDir() {
				return filepath.SkipDir
			}
		}
		if entry.IsDir() {
			if dirtyArtifactDirectory(name) {
				findings = append(findings, newFinding("workspace", name, "dirty-artifact", "generated release artifact directory exists in the repository workspace"))
				return filepath.SkipDir
			}
			return nil
		}
		if dirtyArtifactPath(name) {
			findings = append(findings, newFinding("workspace", name, "dirty-artifact", "generated release artifact exists in the repository workspace"))
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		artifact, err := workspaceFileArtifact(fullPath, entry)
		if err != nil {
			return err
		}
		if artifact {
			findings = append(findings, newFinding("workspace", name, "dirty-artifact", "oversized or compiled artifact exists in the repository workspace"))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan repository workspace: %w", err)
	}
	return deduplicateFindings(findings), nil
}

func workspaceFileArtifact(fullPath string, entry fs.DirEntry) (bool, error) {
	info, err := entry.Info()
	if err != nil {
		return false, err
	}
	if info.Size() > maxSourceFileSize {
		return true, nil
	}
	file, err := os.Open(fullPath)
	if err != nil {
		return false, err
	}
	defer file.Close()
	prefix, err := io.ReadAll(io.LimitReader(file, 4))
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return executableBinary(prefix), nil
}
