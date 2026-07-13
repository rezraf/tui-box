package subscription

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultSubscriptionTimeout   = 15 * time.Second
	MaxSubscriptionResponseBytes = MaxDocumentBytes
	MaxSubscriptionRedirects     = 10
	SubscriptionUserAgent        = "TuiBox/0.1"
)

var (
	errSubscriptionURLInvalid       = errors.New("subscription URL is invalid")
	errSubscriptionHTTPSRequired    = errors.New("subscription URL must use HTTPS")
	errSubscriptionFetchFailed      = errors.New("subscription fetch failed")
	errSubscriptionRedirectRejected = errors.New("subscription redirect was rejected")
	errSubscriptionStatus           = errors.New("subscription server returned an unsuccessful status")
	errSubscriptionResponseTooLarge = errors.New("subscription response exceeds the size limit")
)

type ipResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

type requestOrigin struct {
	host string
	port string
}

type requestOriginContextKey struct{}
type resolvedDialTargetContextKey struct{}

type resolvedDialTarget struct {
	originalAddress string
	port            string
	addresses       []netip.Addr
}

type policyTransport struct {
	base     http.RoundTripper
	resolver ipResolver
	pinDial  bool
}

type Fetcher struct {
	client   *http.Client
	resolver ipResolver
}

func NewFetcher(client *http.Client) *Fetcher {
	return newFetcherWithResolver(client, net.DefaultResolver)
}

func newFetcherWithResolver(client *http.Client, resolver ipResolver) *Fetcher {
	if client == nil {
		client = &http.Client{}
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	configured := *client
	if configured.Timeout <= 0 || configured.Timeout > DefaultSubscriptionTimeout {
		configured.Timeout = DefaultSubscriptionTimeout
	}
	fetcher := &Fetcher{resolver: resolver}
	configured.Transport = newPolicyTransport(configured.Transport, resolver)
	configured.CheckRedirect = fetcher.checkRedirect
	fetcher.client = &configured
	return fetcher
}

func newPolicyTransport(source http.RoundTripper, resolver ipResolver) http.RoundTripper {
	if source == nil {
		source = http.DefaultTransport
	}
	transport, ok := source.(*http.Transport)
	if !ok {
		return &policyTransport{base: source, resolver: resolver}
	}
	configured := transport.Clone()
	baseDial := configured.DialContext
	if baseDial == nil {
		dialer := &net.Dialer{Timeout: DefaultSubscriptionTimeout, KeepAlive: 30 * time.Second}
		baseDial = dialer.DialContext
	}
	configured.Proxy = nil
	configured.DialTLS = nil
	configured.DialTLSContext = nil
	configured.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		target, ok := ctx.Value(resolvedDialTargetContextKey{}).(resolvedDialTarget)
		if !ok || target.originalAddress != address {
			return nil, errSubscriptionFetchFailed
		}
		return target.dial(ctx, network, baseDial)
	}
	return &policyTransport{base: configured, resolver: resolver, pinDial: true}
}

func (transport *policyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if !transport.pinDial {
		return transport.base.RoundTrip(request)
	}
	address, err := dialAddress(request.URL)
	if err != nil {
		return nil, errSubscriptionFetchFailed
	}
	target, ok := request.Context().Value(resolvedDialTargetContextKey{}).(resolvedDialTarget)
	if !ok || target.originalAddress != address {
		origin, hasOrigin := request.Context().Value(requestOriginContextKey{}).(requestOrigin)
		current, originErr := originForURL(request.URL)
		if originErr != nil {
			return nil, errSubscriptionFetchFailed
		}
		target, err = resolveDialTarget(request.Context(), address, hasOrigin && origin != current, transport.resolver)
		if err != nil {
			return nil, err
		}
	}
	return transport.base.RoundTrip(request.WithContext(context.WithValue(request.Context(), resolvedDialTargetContextKey{}, target)))
}

func (fetcher *Fetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return nil, errSubscriptionURLInvalid
	}
	if parsed.Scheme != "https" {
		return nil, errSubscriptionHTTPSRequired
	}
	origin, err := originForURL(parsed)
	if err != nil {
		return nil, errSubscriptionURLInvalid
	}
	ctx = context.WithValue(ctx, requestOriginContextKey{}, origin)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, errSubscriptionURLInvalid
	}
	request.Header.Set("User-Agent", SubscriptionUserAgent)

	response, err := fetcher.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if contextErr := fetchContextError(ctx, err); contextErr != nil {
			return nil, contextErr
		}
		if errors.Is(err, errSubscriptionRedirectRejected) {
			return nil, errSubscriptionRedirectRejected
		}
		return nil, errSubscriptionFetchFailed
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, errSubscriptionStatus
	}
	if response.ContentLength > MaxSubscriptionResponseBytes {
		return nil, errSubscriptionResponseTooLarge
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, MaxSubscriptionResponseBytes+1))
	if err != nil {
		if contextErr := fetchContextError(ctx, err); contextErr != nil {
			return nil, contextErr
		}
		return nil, errSubscriptionFetchFailed
	}
	if len(body) > MaxSubscriptionResponseBytes {
		return nil, errSubscriptionResponseTooLarge
	}
	return body, nil
}

func fetchContextError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}

func (fetcher *Fetcher) checkRedirect(request *http.Request, via []*http.Request) error {
	if request.URL.Scheme != "https" || len(via) > MaxSubscriptionRedirects || len(via) == 0 {
		return errSubscriptionRedirectRejected
	}
	initial, err := originForURL(via[0].URL)
	if err != nil {
		return errSubscriptionRedirectRejected
	}
	current, err := originForURL(request.URL)
	if err != nil {
		return errSubscriptionRedirectRejected
	}
	if current != initial {
		address, err := dialAddress(request.URL)
		if err != nil {
			return errSubscriptionRedirectRejected
		}
		target, err := resolveDialTarget(request.Context(), address, true, fetcher.resolver)
		if err != nil {
			return errSubscriptionRedirectRejected
		}
		*request = *request.WithContext(context.WithValue(request.Context(), resolvedDialTargetContextKey{}, target))
	}
	request.Header.Del("Referer")
	request.Header.Set("User-Agent", SubscriptionUserAgent)
	return nil
}

func checkSubscriptionRedirect(request *http.Request, via []*http.Request) error {
	return (&Fetcher{resolver: net.DefaultResolver}).checkRedirect(request, via)
}

func originForURL(target *url.URL) (requestOrigin, error) {
	if target == nil || target.Scheme != "https" || target.Hostname() == "" {
		return requestOrigin{}, errSubscriptionURLInvalid
	}
	port := target.Port()
	if port == "" {
		port = "443"
	}
	return requestOrigin{host: strings.ToLower(target.Hostname()), port: port}, nil
}

func dialAddress(target *url.URL) (string, error) {
	origin, err := originForURL(target)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(origin.host, origin.port), nil
}

func resolveDialTarget(ctx context.Context, address string, rejectSpecial bool, resolver ipResolver) (resolvedDialTarget, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" || resolver == nil {
		return resolvedDialTarget{}, errSubscriptionRedirectRejected
	}
	if literal, parseErr := netip.ParseAddr(host); parseErr == nil {
		literal = literal.Unmap()
		if literal.Zone() != "" || rejectSpecial && isSpecialUseAddress(literal) {
			return resolvedDialTarget{}, errSubscriptionRedirectRejected
		}
		return resolvedDialTarget{originalAddress: address, port: port, addresses: []netip.Addr{literal}}, nil
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return resolvedDialTarget{}, errSubscriptionRedirectRejected
	}
	validated := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, candidate := range addresses {
		candidate = candidate.Unmap()
		if !candidate.IsValid() || candidate.Zone() != "" || rejectSpecial && isSpecialUseAddress(candidate) {
			return resolvedDialTarget{}, errSubscriptionRedirectRejected
		}
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		validated = append(validated, candidate)
	}
	if len(validated) == 0 {
		return resolvedDialTarget{}, errSubscriptionRedirectRejected
	}
	return resolvedDialTarget{originalAddress: address, port: port, addresses: validated}, nil
}

func (target resolvedDialTarget) dial(ctx context.Context, network string, dial dialContextFunc) (net.Conn, error) {
	if dial == nil || target.port == "" || len(target.addresses) == 0 {
		return nil, errSubscriptionFetchFailed
	}
	var lastErr error
	for _, address := range target.addresses {
		connection, err := dial(ctx, network, net.JoinHostPort(address.String(), target.port))
		if err == nil {
			return connection, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = errSubscriptionFetchFailed
	}
	return nil, lastErr
}

func isSpecialUseAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsPrivate() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsInterfaceLocalMulticast() {
		return true
	}
	for _, prefix := range specialUsePrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

var specialUsePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
}
