package tui

import (
	"context"
	"fmt"
	"io"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/term"
)

type ServiceOpener func(context.Context) (Application, func() error, error)
type TerminalCheck func(io.Reader, io.Writer) bool

type RunConfig struct {
	OpenService ServiceOpener
	Input       io.Reader
	Output      io.Writer
	ErrorOutput io.Writer
	IsTerminal  TerminalCheck

	withoutRenderer bool
}

func Run(ctx context.Context, config RunConfig) error {
	if ctx == nil || config.OpenService == nil || config.Input == nil || config.Output == nil || config.ErrorOutput == nil {
		return ErrInvalidConfiguration
	}
	if config.IsTerminal == nil {
		config.IsTerminal = isTerminal
	}
	if !config.IsTerminal(config.Input, config.Output) {
		_, err := fmt.Fprintln(config.Output, "TuiBox requires an interactive terminal")
		return safeErrorOrNil(err)
	}

	application, closeService, err := config.OpenService(ctx)
	if err != nil {
		if closeService != nil {
			_ = closeService()
		}
		return safeError(err)
	}
	if application == nil || closeService == nil {
		if closeService != nil {
			_ = closeService()
		}
		return ErrOperationFailed
	}

	adapter, err := NewAdapter(application)
	if err != nil {
		_ = closeService()
		return ErrOperationFailed
	}
	model, err := NewModel(ctx, adapter)
	if err != nil {
		_ = closeService()
		return ErrOperationFailed
	}

	options := []tea.ProgramOption{
		tea.WithContext(ctx),
		tea.WithInput(config.Input),
		tea.WithOutput(config.Output),
	}
	if config.withoutRenderer {
		options = append(options, tea.WithoutRenderer())
	} else {
		options = append(options, tea.WithAltScreen())
	}
	_, runErr := tea.NewProgram(model, options...).Run()
	closeErr := closeService()
	if runErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return safeError(ctxErr)
		}
		return safeError(runErr)
	}
	return safeErrorOrNil(closeErr)
}

func safeErrorOrNil(err error) error {
	if err == nil {
		return nil
	}
	return safeError(err)
}

func isTerminal(input io.Reader, output io.Writer) bool {
	inputFile, inputOK := input.(interface{ Fd() uintptr })
	outputFile, outputOK := output.(interface{ Fd() uintptr })
	return inputOK && outputOK && term.IsTerminal(inputFile.Fd()) && term.IsTerminal(outputFile.Fd())
}
