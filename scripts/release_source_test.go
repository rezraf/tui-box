package scripts

import (
	"os/exec"
	"strings"
	"testing"
)

func TestReleaseSourceValidator(t *testing.T) {
	repository := repositoryRoot(t)
	command := exec.Command("go", "run", "./scripts/cmd/release-source")
	command.Dir = repository
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("release source validator: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "release source validation passed") {
		t.Fatalf("release source validator output = %q", output)
	}
}
