package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

const outputBytes = 128 * 1024

func main() {
	if len(os.Args) != 4 || os.Args[2] != "-c" || os.Args[3] != "stdin" {
		os.Exit(64)
	}
	if len(os.Environ()) != 0 {
		os.Exit(65)
	}
	stdinInfo, err := os.Stdin.Stat()
	if err != nil || stdinInfo.Mode()&os.ModeNamedPipe == 0 {
		os.Exit(66)
	}
	config, err := io.ReadAll(os.Stdin)
	if err != nil || len(config) == 0 {
		os.Exit(67)
	}
	digest := sha256.Sum256(config)
	switch os.Args[1] {
	case "check":
		if bytes.Contains(config, []byte("block-check.example.com")) {
			select {}
		}
		if bytes.Contains(config, []byte("fail-check.example.com")) {
			_, _ = os.Stderr.Write(config)
			os.Exit(2)
		}
	case "run":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
		_, _ = fmt.Fprintf(os.Stdout, "uid=%d gid=%d config-sha256=%x config-stdin\n", os.Geteuid(), os.Getegid(), digest)
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), outputBytes))
		<-signals
	default:
		fmt.Fprintln(os.Stderr, "unsupported operation")
		os.Exit(64)
	}
}
