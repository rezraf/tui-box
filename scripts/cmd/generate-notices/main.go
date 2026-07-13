package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type listedPackage struct {
	Module *listedModule
}

type listedModule struct {
	Path    string
	Version string
	Dir     string
	Main    bool
	Replace *listedModule
}

type dependency struct {
	path      string
	version   string
	directory string
	licenses  []licenseFile
}

type licenseFile struct {
	name    string
	content string
}

func main() {
	output := flag.String("output", "THIRD_PARTY_NOTICES", "output file")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal(errors.New("unexpected arguments"))
	}
	dependencies, err := linkedDependencies()
	if err != nil {
		fatal(err)
	}
	contents, err := renderNotices(dependencies)
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*output, []byte(contents), 0o644); err != nil {
		fatal(err)
	}
}

func linkedDependencies() ([]dependency, error) {
	command := exec.Command("go", "list", "-deps", "-json", "./cmd/tuibox", "./cmd/tuiboxd")
	command.Stderr = os.Stderr
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	modules, decodeErr := decodeModules(stdout)
	waitErr := command.Wait()
	if decodeErr != nil {
		return nil, decodeErr
	}
	if waitErr != nil {
		return nil, waitErr
	}

	keys := make([]string, 0, len(modules))
	for key := range modules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	dependencies := make([]dependency, 0, len(keys))
	for _, key := range keys {
		module := modules[key]
		licenses, err := readLicenses(module.Dir)
		if err != nil {
			return nil, fmt.Errorf("%s@%s: %w", module.Path, module.Version, err)
		}
		dependencies = append(dependencies, dependency{
			path: module.Path, version: module.Version, directory: module.Dir, licenses: licenses,
		})
	}
	return dependencies, nil
}

func decodeModules(reader io.Reader) (map[string]listedModule, error) {
	decoder := json.NewDecoder(bufio.NewReader(reader))
	modules := make(map[string]listedModule)
	for {
		var pkg listedPackage
		if err := decoder.Decode(&pkg); errors.Is(err, io.EOF) {
			return modules, nil
		} else if err != nil {
			return nil, err
		}
		if pkg.Module == nil || pkg.Module.Main {
			continue
		}
		module := *pkg.Module
		if module.Replace != nil {
			module = *module.Replace
		}
		if module.Path == "" || module.Version == "" || module.Dir == "" {
			return nil, errors.New("linked module metadata is incomplete")
		}
		modules[module.Path+"@"+module.Version] = module
	}
}

func readLicenses(directory string) ([]licenseFile, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() || !isLicenseName(entry.Name()) {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, errors.New("no top-level license or notice file")
	}
	licenses := make([]licenseFile, 0, len(names))
	for _, name := range names {
		contents, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return nil, err
		}
		normalized := strings.ReplaceAll(string(contents), "\r\n", "\n")
		normalized = strings.TrimRight(normalized, "\n") + "\n"
		licenses = append(licenses, licenseFile{name: name, content: normalized})
	}
	return licenses, nil
}

func isLicenseName(name string) bool {
	upper := strings.ToUpper(name)
	for _, prefix := range []string{"LICENSE", "LICENCE", "COPYING", "NOTICE", "PATENTS"} {
		if upper == prefix || strings.HasPrefix(upper, prefix+".") || strings.HasPrefix(upper, prefix+"-") {
			return true
		}
	}
	return false
}

func renderNotices(dependencies []dependency) (string, error) {
	if len(dependencies) == 0 {
		return "", errors.New("linked dependency inventory is empty")
	}
	var output strings.Builder
	output.WriteString("TuiBox Third-Party Notices\n\n")
	output.WriteString("This file is generated from the pinned Go module graph used by ./cmd/tuibox and ./cmd/tuiboxd.\n")
	output.WriteString("Regenerate it with: sh scripts/generate-third-party-notices.sh THIRD_PARTY_NOTICES\n\n")
	output.WriteString("Corresponding source for TuiBox is available at https://github.com/rezraf/tui-box.\n")
	output.WriteString("Dependency source is available from each module path and version listed below through the Go module ecosystem.\n\n")
	output.WriteString("Linked module inventory:\n")
	for _, item := range dependencies {
		fmt.Fprintf(&output, "- %s %s\n", item.path, item.version)
	}
	for _, item := range dependencies {
		output.WriteString("\n===============================================================================\n")
		fmt.Fprintf(&output, "%s %s\n", item.path, item.version)
		fmt.Fprintf(&output, "Source: https://pkg.go.dev/%s@%s\n", item.path, item.version)
		for _, license := range item.licenses {
			fmt.Fprintf(&output, "\n--- %s ---\n", license.name)
			output.WriteString(license.content)
		}
	}
	return output.String(), nil
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "generate third-party notices: %v\n", err)
	os.Exit(1)
}
