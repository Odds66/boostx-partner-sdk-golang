// Package client provides an HTTP client for outbound BoostX Partner API calls.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// DefaultBaseURL is the production BoostX partners S2S API base URL.
const DefaultBaseURL = "https://partners-s2s.boostx.cloud"

// APIError is any answer other than BoostX's acceptance, 200 {"result":{"ok":true}}:
// a 3xx (redirects are not followed), a 4xx, a 5xx, or a 2xx with another body
// (Message "unexpected response").
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("boostx api error %d: %s", e.StatusCode, e.Message)
}

// IsRetryable reports whether err from SubmitSettlement left the settlement
// undelivered for a reason that re-sending the same params later can overcome.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	if apiErr, ok := errors.AsType[*APIError](err); ok {
		// The unknown-partner 404 is JSON "not found"; any other 404 is a route, a wrong base URL like a 3xx.
		if apiErr.StatusCode == http.StatusNotFound {
			return apiErr.Message != "not found"
		}
		return apiErr.StatusCode < 400 || apiErr.StatusCode >= 500 || apiErr.StatusCode == http.StatusUnauthorized
	}
	return !errors.Is(err, tokens.ErrMissingClaim) && !errors.Is(err, tokens.ErrInvalidClaim) && !errors.Is(err, keys.ErrUnknownPartner)
}

// Client makes outbound HTTP calls to the BoostX Partner API.
type Client struct {
	keys       KeyStore
	baseURL    string
	httpClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL overrides the default base URL. It takes the base URL or the
// settlement endpoint URL; surrounding whitespace and trailing slashes are ignored.
func WithBaseURL(url string) Option {
	return func(c *Client) { c.baseURL = url }
}

// WithHTTPClient provides a custom http.Client; nil keeps the default client.
// The client is used as is: set its Timeout, or give SubmitSettlement a context
// with a deadline. Redirects are never followed.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// New creates a Client with the given key store and options. Panics if ks is nil.
func New(ks KeyStore, opts ...Option) *Client {
	if ks == nil {
		panic("boostx: nil key store")
	}
	c := &Client{
		keys:       ks,
		baseURL:    DefaultBaseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	c.baseURL = strings.TrimSuffix(strings.TrimRight(strings.TrimSpace(c.baseURL), "/"), settlementPath)
	return c
}

// doAPIRequest POSTs body as JSON, following no redirect, and returns nil only
// for a 2xx carrying {"result":{"ok":true}}. Any other answer is an *APIError.
func (c *Client) doAPIRequest(ctx context.Context, path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	hc := *c.httpClient // a copy, so the caller's client is never modified
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var envelope struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &envelope) == nil && envelope.Error != "" {
			return &APIError{StatusCode: resp.StatusCode, Message: envelope.Error}
		}
		return &APIError{StatusCode: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	}
	if readErr != nil {
		return fmt.Errorf("read response: %w", readErr)
	}
	var accepted struct {
		Result struct {
			OK bool `json:"ok"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &accepted) != nil || !accepted.Result.OK {
		return &APIError{StatusCode: resp.StatusCode, Message: "unexpected response"}
	}
	return nil
}
