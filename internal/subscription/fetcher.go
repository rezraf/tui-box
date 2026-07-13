package subscription

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
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

type Fetcher struct {
	client *http.Client
}

func NewFetcher(client *http.Client) *Fetcher {
	if client == nil {
		client = &http.Client{}
	}
	configured := *client
	if configured.Timeout <= 0 || configured.Timeout > DefaultSubscriptionTimeout {
		configured.Timeout = DefaultSubscriptionTimeout
	}
	configured.CheckRedirect = checkSubscriptionRedirect
	return &Fetcher{client: &configured}
}

func (fetcher *Fetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return nil, errSubscriptionURLInvalid
	}
	if parsed.Scheme != "https" {
		return nil, errSubscriptionHTTPSRequired
	}

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
		return nil, errSubscriptionFetchFailed
	}
	if len(body) > MaxSubscriptionResponseBytes {
		return nil, errSubscriptionResponseTooLarge
	}
	return body, nil
}

func checkSubscriptionRedirect(request *http.Request, via []*http.Request) error {
	if request.URL.Scheme != "https" || len(via) > MaxSubscriptionRedirects {
		return errSubscriptionRedirectRejected
	}
	request.Header.Del("Referer")
	request.Header.Set("User-Agent", SubscriptionUserAgent)
	return nil
}
