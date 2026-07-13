package main

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

const outputBytes = 128 * 1024

func main() {
	if len(os.Args) != 4 || os.Args[2] != "-c" || os.Args[3] != "/dev/fd/3" {
		os.Exit(64)
	}
	if len(os.Environ()) != 0 {
		os.Exit(65)
	}
	config, err := os.ReadFile(os.Args[3])
	if err != nil {
		os.Exit(66)
	}
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
		_, _ = fmt.Fprintf(os.Stdout, "uid=%d gid=%d config-readable\n", os.Geteuid(), os.Getegid())
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), outputBytes))
		<-signals
	default:
		fmt.Fprintln(os.Stderr, "unsupported operation")
		os.Exit(64)
	}
}
