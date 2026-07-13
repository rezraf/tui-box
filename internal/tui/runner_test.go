package tui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRunNonTTYReturnsWithoutOpeningServiceOrHanging(t *testing.T) {
	opened := 0
	var output bytes.Buffer
	err := Run(context.Background(), RunConfig{
		OpenService: func(context.Context) (Application, func() error, error) {
			opened++
			return &fakeApplication{}, func() error { return nil }, nil
		},
		Input:       strings.NewReader(""),
		Output:      &output,
		ErrorOutput: io.Discard,
		IsTerminal:  func(io.Reader, io.Writer) bool { return false },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if opened != 0 {
		t.Fatalf("service opens = %d, want 0", opened)
	}
	if output.String() != "TuiBox requires an interactive terminal\n" {
		t.Fatalf("output = %q", output.String())
	}
}

func TestRunInteractiveProgramQuitsAndClosesService(t *testing.T) {
	opened := 0
	closed := 0
	var output bytes.Buffer
	err := Run(context.Background(), RunConfig{
		OpenService: func(context.Context) (Application, func() error, error) {
			opened++
			return &fakeApplication{}, func() error {
				closed++
				return nil
			}, nil
		},
		Input:           strings.NewReader("q"),
		Output:          &output,
		ErrorOutput:     io.Discard,
		IsTerminal:      func(io.Reader, io.Writer) bool { return true },
		withoutRenderer: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if opened != 1 || closed != 1 {
		t.Fatalf("service lifecycle = open %d close %d, want 1/1", opened, closed)
	}
}

func TestRunMapsHostileOpenAndCloseErrorsToStableFailure(t *testing.T) {
	secret := "https://user:password@proxy.example.com/private?token=value RPC payload"
	tests := []struct {
		name string
		open ServiceOpener
	}{
		{
			name: "open",
			open: func(context.Context) (Application, func() error, error) {
				return nil, nil, errors.New(secret)
			},
		},
		{
			name: "close",
			open: func(context.Context) (Application, func() error, error) {
				return &fakeApplication{}, func() error { return errors.New(secret) }, nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Run(context.Background(), RunConfig{
				OpenService:     test.open,
				Input:           strings.NewReader("q"),
				Output:          io.Discard,
				ErrorOutput:     io.Discard,
				IsTerminal:      func(io.Reader, io.Writer) bool { return true },
				withoutRenderer: true,
			})
			if err != ErrOperationFailed {
				t.Fatalf("error = %v (%T), want exact %v", err, err, ErrOperationFailed)
			}
		})
	}
}
