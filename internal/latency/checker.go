package latency

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/rezraf/tui-box/internal/domain"
	"github.com/rezraf/tui-box/internal/redact"
)

const (
	MaxProbeTimeout = 30 * time.Second
	MaxParallelism  = 128
)

var (
	ErrInvalidConfiguration = errors.New("latency checker configuration is invalid")
	ErrNoAvailableEndpoint  = errors.New("no endpoint passed the latency check")
)

type Status string

const (
	StatusSuccess     Status = "success"
	StatusUnavailable Status = "unavailable"
	StatusUnsupported Status = "unsupported"
)

type Result struct {
	EndpointID string          `json:"endpoint_id"`
	Protocol   domain.Protocol `json:"protocol"`
	Duration   time.Duration   `json:"duration"`
	Status     Status          `json:"status"`
	Error      string          `json:"error,omitempty"`
}

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type Config struct {
	Dialer      Dialer
	Timeout     time.Duration
	MaxParallel int
}

type Checker struct {
	dialer      Dialer
	timeout     time.Duration
	maxParallel int
}

func NewChecker(config Config) (*Checker, error) {
	if config.Timeout <= 0 || config.Timeout > MaxProbeTimeout || config.MaxParallel <= 0 || config.MaxParallel > MaxParallelism {
		return nil, ErrInvalidConfiguration
	}
	if config.Dialer == nil {
		config.Dialer = &net.Dialer{Timeout: config.Timeout}
	}
	return &Checker{dialer: config.Dialer, timeout: config.Timeout, maxParallel: config.MaxParallel}, nil
}

// Check probes endpoints with a fixed-size worker pool and preserves input order.
func (checker *Checker) Check(ctx context.Context, endpoints []domain.Endpoint) []Result {
	if len(endpoints) == 0 {
		return []Result{}
	}
	if ctx == nil {
		ctx = context.Background()
	}

	results := make([]Result, len(endpoints))
	for index, endpoint := range endpoints {
		results[index] = Result{EndpointID: endpoint.ID, Protocol: endpoint.Protocol}
	}

	jobs := make(chan int)
	workers := min(checker.maxParallel, len(endpoints))
	done := make(chan struct{}, workers)
	for range workers {
		go func() {
			defer func() { done <- struct{}{} }()
			for index := range jobs {
				if ctx.Err() != nil {
					return
				}
				results[index] = checker.checkOne(ctx, endpoints[index])
			}
		}()
	}

sendJobs:
	for index := range endpoints {
		select {
		case jobs <- index:
		case <-ctx.Done():
			break sendJobs
		}
	}
	close(jobs)
	for range workers {
		<-done
	}
	if err := ctx.Err(); err != nil {
		for index := range results {
			if results[index].Status == "" {
				results[index].Status = StatusUnavailable
				results[index].Error = err.Error()
			}
		}
	}
	return results
}

func (checker *Checker) checkOne(ctx context.Context, endpoint domain.Endpoint) Result {
	result := Result{EndpointID: endpoint.ID, Protocol: endpoint.Protocol}
	if !supportsTCPProbe(endpoint.Protocol) {
		result.Status = StatusUnsupported
		result.Error = "TCP latency probe is unsupported for this protocol"
		return result
	}
	if err := endpoint.Validate(); err != nil {
		result.Status = StatusUnavailable
		result.Error = redact.StringSensitive(err.Error(), endpoint.Host, endpoint.UUID, endpoint.Password)
		return result
	}

	if err := ctx.Err(); err != nil {
		result.Status = StatusUnavailable
		result.Error = err.Error()
		return result
	}

	address := net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))
	probeContext, cancel := context.WithTimeout(ctx, checker.timeout)
	defer cancel()
	started := time.Now()
	connection, err := checker.dialer.DialContext(probeContext, "tcp", address)
	elapsed := time.Since(started)
	if contextErr := probeContext.Err(); contextErr != nil {
		if connection != nil {
			_ = connection.Close()
		}
		result.Status = StatusUnavailable
		result.Error = contextErr.Error()
		return result
	}
	if err != nil {
		result.Status = StatusUnavailable
		result.Error = redact.StringSensitive(err.Error(), address, endpoint.Host, endpoint.UUID, endpoint.Password)
		return result
	}
	if connection == nil {
		result.Status = StatusUnavailable
		result.Error = "latency dialer returned nil connection"
		return result
	}
	_ = connection.Close()
	result.Status = StatusSuccess
	result.Duration = elapsed
	return result
}

func supportsTCPProbe(protocol domain.Protocol) bool {
	switch protocol {
	case domain.ProtocolVLESS, domain.ProtocolVMess, domain.ProtocolTrojan, domain.ProtocolShadowsocks:
		return true
	default:
		return false
	}
}

// Best selects the lowest successful latency, resolving equal durations by endpoint ID.
func Best(results []Result) (Result, error) {
	var best Result
	found := false
	for _, result := range results {
		if result.Status != StatusSuccess {
			continue
		}
		if !found || result.Duration < best.Duration || result.Duration == best.Duration && result.EndpointID < best.EndpointID {
			best = result
			found = true
		}
	}
	if !found {
		return Result{}, ErrNoAvailableEndpoint
	}
	return best, nil
}
