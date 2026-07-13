package subscription

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
)

const parserProbeAllocationLimit = 2 << 20

func TestStructuredParsersSkipOversizedEntryWithoutMaterializingIt(t *testing.T) {
	padding := strings.Repeat("x", MaxEntryBytes+1)
	documents := map[string][]byte{
		"sing-box": []byte(`{"outbounds":[{"type":"shadowsocks","tag":"oversized","server":"example.com","server_port":443,"method":"aes-256-gcm","password":"secret","padding":"` + padding + `"},{"type":"shadowsocks","tag":"valid","server":"valid.example.com","server_port":443,"method":"aes-256-gcm","password":"secret"}]}`),
		"Clash":    []byte("proxies:\n  - name: oversized\n    type: ss\n    server: example.com\n    port: 443\n    cipher: aes-256-gcm\n    password: secret\n    padding: " + padding + "\n  - name: valid\n    type: ss\n    server: valid.example.com\n    port: 443\n    cipher: aes-256-gcm\n    password: secret\n"),
	}
	for name, document := range documents {
		t.Run(name, func(t *testing.T) {
			result, err := Parse(testSubscriptionID, document)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if len(result.Endpoints) != 1 || result.Endpoints[0].Host != "valid.example.com" {
				t.Fatalf("endpoints = %#v, want one valid endpoint", result.Endpoints)
			}
			if len(result.Warnings) != 1 || result.Warnings[0].Code != "entry_too_large" {
				t.Fatalf("warnings = %#v, want one oversized warning", result.Warnings)
			}
		})
	}
}

func TestStructuredParserLimitsAreEnforcedBeforeMaterialization(t *testing.T) {
	if probe := os.Getenv("TUIBOX_PARSER_RESOURCE_PROBE"); probe != "" {
		runParserResourceProbe(t, probe)
		return
	}
	for _, probe := range []string{
		"singbox-too-many",
		"clash-too-many",
		"singbox-oversized-entry",
		"clash-oversized-entry",
		"singbox-deep-nesting",
		"clash-deep-nesting",
	} {
		probe := probe
		t.Run(probe, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestStructuredParserLimitsAreEnforcedBeforeMaterialization$", "-test.count=1")
			command.Env = append(os.Environ(),
				"TUIBOX_PARSER_RESOURCE_PROBE="+probe,
				"GOMEMLIMIT=48MiB",
			)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("resource probe failed: %v\n%s", err, output)
			}
		})
	}
}

func runParserResourceProbe(t *testing.T, probe string) {
	t.Helper()
	debug.SetMemoryLimit(48 << 20)
	document, expected := parserProbeDocument(t, probe)
	if len(document) > MaxDocumentBytes {
		t.Fatalf("probe document size = %d, exceeds MaxDocumentBytes", len(document))
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	result, err := Parse(testSubscriptionID, document)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if !errors.Is(err, expected) {
		t.Fatalf("Parse() error = %v, want %v; endpoints=%d warnings=%d", err, expected, len(result.Endpoints), len(result.Warnings))
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("Parse() allocated %d bytes", allocated)
	if allocated > parserProbeAllocationLimit {
		t.Fatalf("Parse() allocated %d bytes, limit %d", allocated, parserProbeAllocationLimit)
	}
}

func parserProbeDocument(t *testing.T, probe string) ([]byte, error) {
	t.Helper()
	switch probe {
	case "singbox-too-many":
		entry := `{"type":"direct"}`
		return []byte(`{"outbounds":[` + strings.TrimSuffix(strings.Repeat(entry+",", MaxEntries+1), ",") + `]}`), errTooManyEntries
	case "clash-too-many":
		return []byte("proxies:\n" + strings.Repeat("  - {type: direct}\n", MaxEntries+1)), errTooManyEntries
	case "singbox-oversized-entry":
		padding := strings.Repeat("x", MaxEntryBytes+1)
		return []byte(`{"outbounds":[{"type":"shadowsocks","tag":"oversized","server":"example.com","server_port":443,"method":"aes-256-gcm","password":"secret","padding":"` + padding + `"}]}`), errMalformedDocument
	case "clash-oversized-entry":
		padding := strings.Repeat("x", MaxEntryBytes+1)
		return []byte("proxies:\n  - name: oversized\n    type: ss\n    server: example.com\n    port: 443\n    cipher: aes-256-gcm\n    password: secret\n    padding: " + padding + "\n"), errMalformedDocument
	case "singbox-deep-nesting":
		depth := maxJSONNestingDepth + 1
		return []byte(`{"outbounds":[{"type":"direct","nested":` + strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth) + `}]}`), errMalformedDocument
	case "clash-deep-nesting":
		depth := maxJSONNestingDepth + 1
		return []byte("proxies:\n  - name: deep\n    type: ss\n    server: example.com\n    port: 443\n    cipher: aes-256-gcm\n    password: secret\n    nested: " + strings.Repeat("[", depth) + strconv.Itoa(depth) + strings.Repeat("]", depth) + "\n"), errMalformedDocument
	default:
		t.Fatal(fmt.Sprintf("unknown parser resource probe %q", probe))
		return nil, nil
	}
}
