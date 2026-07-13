package main

import (
	"fmt"
	"io"
	"os"

	"github.com/rezraf/tui-box/scripts/releasecheck"
)

func main() {
	os.Exit(run(os.Stdout, os.Stderr))
}

func run(stdout, stderr io.Writer) int {
	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "release source validation failed: %v\n", err)
		return 1
	}
	report, err := releasecheck.ValidateRepository(root)
	if err != nil {
		fmt.Fprintf(stderr, "release source validation failed: %v\n", err)
		return 1
	}
	if len(report.Findings) != 0 {
		for _, finding := range report.Findings {
			fmt.Fprintln(stderr, finding.String())
		}
		fmt.Fprintf(stderr, "release source validation failed: %d finding(s)\n", len(report.Findings))
		return 1
	}
	fmt.Fprintf(stdout, "release source validation passed: %d tracked files, %d future archive files\n", report.TrackedFiles, report.ArchiveFiles)
	return 0
}
