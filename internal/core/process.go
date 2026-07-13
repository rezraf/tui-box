package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	commandCheck = "check"
	commandRun   = "run"

	inheritedConfigPath = "/dev/fd/3"

	maxGeneratedConfigBytes = 128 * 1024
	maxCoreOutputBytes      = 64 * 1024
	processWaitDelay        = 2 * time.Second
)

var (
	ErrInvalidExecutable      = errors.New("invalid sing-box executable")
	ErrUnsafeRuntimeRoot      = errors.New("unsafe runtime root")
	ErrRunnerClosed           = errors.New("sing-box runner is closed")
	ErrPreparedConfigNotOwned = errors.New("prepared config is not owned by this runner")
	ErrPreparedConfigClosed   = errors.New("prepared config is closed")
	ErrPreparedConfigChanged  = errors.New("prepared config changed")
	ErrConfigNotChecked       = errors.New("prepared config has not passed sing-box check")
	ErrCoreCheckFailed        = errors.New("sing-box config check failed")
	ErrCoreStartFailed        = errors.New("sing-box process start failed")
)

type Runner interface {
	Prepare(request ConnectionRequest) (*PreparedConfig, error)
	Check(ctx context.Context, prepared *PreparedConfig) error
	Start(ctx context.Context, prepared *PreparedConfig) (Process, error)
	Close() error
}

type PreparedConfig struct {
	runner *execRunner
	closed atomic.Bool
}

func (prepared *PreparedConfig) Close() error {
	if prepared == nil || prepared.runner == nil {
		return nil
	}
	return prepared.runner.closePrepared(prepared)
}

type Process interface {
	Signal(signal os.Signal) error
	Kill() error
	Wait() error
	Output() []byte
}

type preparedState struct {
	name          string
	digest        [sha256.Size]byte
	checkedDigest [sha256.Size]byte
	checked       bool
	request       ConnectionRequest
}

type execRunner struct {
	executable     string
	executableInfo os.FileInfo
	runtimeRoot    *os.Root

	mu       sync.Mutex
	prepared map[*PreparedConfig]*preparedState
	closed   bool
}

func NewRunner(executable, runtimeDirectory string) (Runner, error) {
	trustedPath, executableInfo, err := inspectExecutable(executable)
	if err != nil {
		return nil, err
	}
	runtimeRoot, err := openRuntimeRoot(runtimeDirectory)
	if err != nil {
		return nil, err
	}
	return &execRunner{
		executable:     trustedPath,
		executableInfo: executableInfo,
		runtimeRoot:    runtimeRoot,
		prepared:       make(map[*PreparedConfig]*preparedState),
	}, nil
}

func inspectExecutable(input string) (string, os.FileInfo, error) {
	if !filepath.IsAbs(input) {
		return "", nil, ErrInvalidExecutable
	}
	inputInfo, err := os.Lstat(input)
	if err != nil || inputInfo.Mode()&os.ModeSymlink != 0 || !inputInfo.Mode().IsRegular() {
		return "", nil, ErrInvalidExecutable
	}
	resolved, err := filepath.EvalSymlinks(input)
	if err != nil || !filepath.IsAbs(resolved) {
		return "", nil, ErrInvalidExecutable
	}
	info, err := os.Lstat(resolved)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", nil, ErrInvalidExecutable
	}
	owner, ok := fileOwnerID(info)
	if !ok || owner != os.Geteuid() || info.Mode().Perm()&0o100 == 0 || info.Mode().Perm()&0o022 != 0 {
		return "", nil, ErrInvalidExecutable
	}
	if err := inspectTrustedParents(filepath.Dir(resolved)); err != nil {
		return "", nil, err
	}
	return resolved, info, nil
}

func inspectTrustedParents(directory string) error {
	for {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return ErrInvalidExecutable
		}
		owner, ok := fileOwnerID(info)
		if !ok || owner != 0 && owner != os.Geteuid() {
			return ErrInvalidExecutable
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return nil
		}
		directory = parent
	}
}

func openRuntimeRoot(directory string) (*os.Root, error) {
	if !filepath.IsAbs(directory) {
		return nil, ErrUnsafeRuntimeRoot
	}
	before, err := os.Lstat(directory)
	if err != nil || !validRuntimeRootInfo(before) {
		return nil, ErrUnsafeRuntimeRoot
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, ErrUnsafeRuntimeRoot
	}
	after, err := root.Stat(".")
	if err != nil || !validRuntimeRootInfo(after) || !os.SameFile(before, after) {
		_ = root.Close()
		return nil, ErrUnsafeRuntimeRoot
	}
	return root, nil
}

func validRuntimeRootInfo(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return false
	}
	owner, ok := fileOwnerID(info)
	return ok && owner == os.Geteuid()
}

func (runner *execRunner) Prepare(request ConnectionRequest) (*PreparedConfig, error) {
	config, err := GenerateConfig(request)
	if err != nil {
		return nil, err
	}
	if len(config) > maxGeneratedConfigBytes {
		return nil, ErrPreparedConfigChanged
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.closed {
		return nil, ErrRunnerClosed
	}
	if err := runner.inspectRuntimeRoot(); err != nil {
		return nil, err
	}

	token, err := uniqueConfigToken()
	if err != nil {
		return nil, ErrPreparedConfigChanged
	}
	temporaryName := ".config-" + token + ".tmp"
	finalName := "config-" + token + ".json"
	if _, err := runner.runtimeRoot.Lstat(finalName); err == nil || !errors.Is(err, os.ErrNotExist) {
		return nil, ErrPreparedConfigChanged
	}

	file, err := runner.runtimeRoot.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, ErrPreparedConfigChanged
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = runner.runtimeRoot.Remove(temporaryName)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, ErrPreparedConfigChanged
	}
	if err := validatePreparedFile(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	writeErr := writeConfigFile(file, config)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return nil, ErrPreparedConfigChanged
	}
	if err := runner.runtimeRoot.Rename(temporaryName, finalName); err != nil {
		return nil, ErrPreparedConfigChanged
	}
	removeTemporary = false
	if err := syncRuntimeRoot(runner.runtimeRoot); err != nil {
		_ = runner.runtimeRoot.Remove(finalName)
		return nil, ErrPreparedConfigChanged
	}

	prepared := &PreparedConfig{runner: runner}
	runner.prepared[prepared] = &preparedState{
		name:    finalName,
		digest:  sha256.Sum256(config),
		request: request,
	}
	return prepared, nil
}

func uniqueConfigToken() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func validatePreparedFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return ErrPreparedConfigChanged
	}
	owner, ok := fileOwnerID(info)
	if !ok || owner != os.Geteuid() {
		return ErrPreparedConfigChanged
	}
	return nil
}

func writeConfigFile(file *os.File, config []byte) error {
	if _, err := file.Write(config); err != nil {
		return err
	}
	return file.Sync()
}

func syncRuntimeRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func (runner *execRunner) Check(ctx context.Context, prepared *PreparedConfig) error {
	if ctx == nil {
		return ErrCoreCheckFailed
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	state, err := runner.preparedState(prepared)
	if err != nil {
		return err
	}
	state.checked = false
	if err := runner.inspectRuntimeRoot(); err != nil {
		return err
	}
	if err := runner.inspectExecutable(); err != nil {
		return err
	}
	file, digest, err := runner.openVerifiedConfig(state)
	if err != nil {
		return err
	}
	defer file.Close()

	output := newBoundedBuffer(maxCoreOutputBytes)
	command := runner.command(ctx, commandCheck, file, state.request)
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return ErrCoreCheckFailed
	}
	state.checkedDigest = digest
	state.checked = true
	return nil
}

func (runner *execRunner) Start(ctx context.Context, prepared *PreparedConfig) (Process, error) {
	if ctx == nil {
		return nil, ErrCoreStartFailed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	state, err := runner.preparedState(prepared)
	if err != nil {
		return nil, err
	}
	if !state.checked || state.checkedDigest != state.digest {
		return nil, ErrConfigNotChecked
	}
	if err := runner.inspectRuntimeRoot(); err != nil {
		return nil, err
	}
	if err := runner.inspectExecutable(); err != nil {
		return nil, err
	}
	file, digest, err := runner.openVerifiedConfig(state)
	if err != nil {
		return nil, err
	}
	if digest != state.checkedDigest {
		_ = file.Close()
		return nil, ErrPreparedConfigChanged
	}

	output := newBoundedBuffer(maxCoreOutputBytes)
	command := runner.command(ctx, commandRun, file, state.request)
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		_ = file.Close()
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, ErrCoreStartFailed
	}
	if err := file.Close(); err != nil {
		_ = signalProcessGroup(command.Process.Pid, syscall.SIGKILL)
		_ = command.Wait()
		return nil, ErrCoreStartFailed
	}
	return newManagedProcess(command, output), nil
}

func (runner *execRunner) preparedState(prepared *PreparedConfig) (*preparedState, error) {
	if runner.closed {
		return nil, ErrRunnerClosed
	}
	if prepared == nil || prepared.runner != runner {
		return nil, ErrPreparedConfigNotOwned
	}
	if prepared.closed.Load() {
		return nil, ErrPreparedConfigClosed
	}
	state, exists := runner.prepared[prepared]
	if !exists {
		return nil, ErrPreparedConfigClosed
	}
	return state, nil
}

func (runner *execRunner) openVerifiedConfig(state *preparedState) (*os.File, [sha256.Size]byte, error) {
	file, err := runner.runtimeRoot.Open(state.name)
	if err != nil {
		return nil, [sha256.Size]byte{}, ErrPreparedConfigChanged
	}
	if err := validatePreparedFile(file); err != nil {
		_ = file.Close()
		return nil, [sha256.Size]byte{}, err
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maxGeneratedConfigBytes+1))
	if err != nil || written > maxGeneratedConfigBytes {
		_ = file.Close()
		return nil, [sha256.Size]byte{}, ErrPreparedConfigChanged
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	if digest != state.digest {
		_ = file.Close()
		return nil, [sha256.Size]byte{}, ErrPreparedConfigChanged
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, [sha256.Size]byte{}, ErrPreparedConfigChanged
	}
	return file, digest, nil
}

func (runner *execRunner) inspectRuntimeRoot() error {
	info, err := runner.runtimeRoot.Stat(".")
	if err != nil || !validRuntimeRootInfo(info) {
		return ErrUnsafeRuntimeRoot
	}
	return nil
}

func (runner *execRunner) inspectExecutable() error {
	resolved, info, err := inspectExecutable(runner.executable)
	if err != nil || resolved != runner.executable || !os.SameFile(runner.executableInfo, info) {
		return ErrInvalidExecutable
	}
	return nil
}

func (runner *execRunner) command(ctx context.Context, operation string, config *os.File, request ConnectionRequest) *exec.Cmd {
	command := exec.CommandContext(ctx, runner.executable, operation, "-c", inheritedConfigPath)
	command.Env = []string{}
	command.ExtraFiles = []*os.File{config}
	command.WaitDelay = processWaitDelay
	configureCommand(command, operation, request)
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return signalProcessGroup(command.Process.Pid, syscall.SIGKILL)
	}
	return command
}

func (runner *execRunner) closePrepared(prepared *PreparedConfig) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.closed {
		prepared.closed.Store(true)
		return nil
	}
	if prepared.runner != runner {
		return ErrPreparedConfigNotOwned
	}
	if prepared.closed.Load() {
		return nil
	}
	state, exists := runner.prepared[prepared]
	if !exists {
		prepared.closed.Store(true)
		return nil
	}
	if err := runner.runtimeRoot.Remove(state.name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	delete(runner.prepared, prepared)
	prepared.closed.Store(true)
	return nil
}

func (runner *execRunner) Close() error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.closed {
		return nil
	}
	var closeErrors []error
	for prepared, state := range runner.prepared {
		if err := runner.runtimeRoot.Remove(state.name); err != nil && !errors.Is(err, os.ErrNotExist) {
			closeErrors = append(closeErrors, err)
		}
		prepared.closed.Store(true)
		delete(runner.prepared, prepared)
	}
	if err := runner.runtimeRoot.Close(); err != nil {
		closeErrors = append(closeErrors, err)
	}
	runner.closed = true
	return errors.Join(closeErrors...)
}

type boundedBuffer struct {
	mu        sync.Mutex
	remaining int
	content   []byte
}

func newBoundedBuffer(limit int) *boundedBuffer {
	return &boundedBuffer{remaining: limit, content: make([]byte, 0, limit)}
}

func (buffer *boundedBuffer) Write(input []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	inputLength := len(input)
	if buffer.remaining > 0 {
		kept := min(buffer.remaining, inputLength)
		buffer.content = append(buffer.content, input[:kept]...)
		buffer.remaining -= kept
	}
	return inputLength, nil
}

func (buffer *boundedBuffer) Bytes() []byte {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return append([]byte(nil), buffer.content...)
}

type managedProcess struct {
	command *exec.Cmd
	output  *boundedBuffer
	done    chan struct{}

	waitOnce sync.Once
	waitErr  error
}

func newManagedProcess(command *exec.Cmd, output *boundedBuffer) *managedProcess {
	return &managedProcess{command: command, output: output, done: make(chan struct{})}
}

func (process *managedProcess) Signal(signal os.Signal) error {
	syscallSignal, ok := signal.(syscall.Signal)
	if !ok {
		return fmt.Errorf("unsupported process signal")
	}
	select {
	case <-process.done:
		return os.ErrProcessDone
	default:
		return signalProcessGroup(process.command.Process.Pid, syscallSignal)
	}
}

func (process *managedProcess) Kill() error {
	select {
	case <-process.done:
		return os.ErrProcessDone
	default:
		return signalProcessGroup(process.command.Process.Pid, syscall.SIGKILL)
	}
}

func (process *managedProcess) Wait() error {
	process.waitOnce.Do(func() {
		process.waitErr = process.command.Wait()
		close(process.done)
	})
	<-process.done
	return process.waitErr
}

func (process *managedProcess) Output() []byte {
	return process.output.Bytes()
}
