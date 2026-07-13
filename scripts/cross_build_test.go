package scripts

import (
	"os"
	"strings"
	"testing"
)

func TestCrossBuildCoversBothBinariesAndAllSupportedTargets(t *testing.T) {
	contents, err := os.ReadFile("cross-build.sh")
	if err != nil {
		t.Fatalf("read cross-build.sh: %v", err)
	}
	script := string(contents)
	for _, target := range []string{"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64"} {
		if !strings.Contains(script, target) {
			t.Fatalf("cross-build.sh does not include %s", target)
		}
	}
	if !strings.Contains(script, "go build ./cmd/tuibox ./cmd/tuiboxd") {
		t.Fatal("cross-build.sh does not explicitly build both binaries")
	}
}
