// Package client provides an HTTP client for outbound BoostX Partner API calls.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
)

// DefaultBaseURL is the production BoostX partners S2S API base URL.
const DefaultBaseURL = "https://partners-s2s.boostx.cloud"

// defaultTimeout bounds a SubmitSettlement attempt whose http.Client sets no Timeout.
const defaultTimeout = 30 * time.Second

// APIError is any answer other than BoostX's acceptance, a 2xx whose body is
// {"result":{"ok":true}}: a 3xx (redirects are not followed), a 4xx, a 5xx, or
// a 2xx with another body (Message "unexpected response"). Message is otherwise the body's "error"
// string, or "HTTP <status>" without one. StatusCode and Message help diagnose
// a settlement BoostX keeps refusing; they never mean it is lost.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("boostx api error %d: %s", e.StatusCode, e.Message)
}

// Client makes outbound HTTP calls to the BoostX Partner API.
type Client struct {
	keys       KeyStore
	baseURL    string
	httpClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL overrides the default base URL: http:// or https:// and a host, or
// the settlement endpoint URL. Surrounding ASCII whitespace (space, tab, CR,
// LF, VT, FF) and trailing slashes are ignored; New panics on any other URL.
func WithBaseURL(url string) Option {
	return func(c *Client) { c.baseURL = url }
}

// WithHTTPClient provides a custom http.Client; nil keeps the default client.
// Its Timeout, or 30 s when it is 0, bounds each SubmitSettlement attempt from
// the key lookup to the end of the response; New panics on a negative one.
// Redirects are never followed.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// New creates a Client with the given key store and options. Panics if ks is
// nil (a nil *keys.MemoryKeyStore included; a nil pointer of your own store type
// is not caught), if the base URL is invalid or the Timeout negative.
func New(ks KeyStore, opts ...Option) *Client {
	if m, ok := ks.(*keys.MemoryKeyStore); ks == nil || ok && m == nil {
		panic("boostx: nil key store")
	}
	c := &Client{
		keys:       ks,
		baseURL:    DefaultBaseURL,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
	for _, o := range opts {
		o(c)
	}
	if c.httpClient.Timeout < 0 {
		panic("boostx: negative http.Client Timeout")
	}
	c.baseURL = strings.TrimSuffix(strings.TrimRight(strings.Trim(c.baseURL, " \t\n\v\f\r"), "/"), settlementPath)
	lower := strings.ToLower(c.baseURL)
	u, err := url.Parse(c.baseURL)
	if err != nil || u.Hostname() == "" || !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		panic("boostx: invalid base URL")
	}
	return c
}

// doAPIRequest POSTs body as JSON, following no redirect, and returns nil only
// for a 2xx carrying {"result":{"ok":true}}. Any other answer is an *APIError;
// a failed body read, a cancellation included, is returned wrapped whatever the
// status.
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
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	answer := jsonObject(raw)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var msg string
		if json.Unmarshal(answer["error"], &msg) != nil || msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return &APIError{StatusCode: resp.StatusCode, Message: msg}
	}
	var ok bool
	if json.Unmarshal(jsonObject(answer["result"])["ok"], &ok) != nil || !ok {
		return &APIError{StatusCode: resp.StatusCode, Message: "unexpected response"}
	}
	return nil
}

// jsonObject returns the members of raw by exact name, the last of a repeated
// name winning, or nil unless raw is one JSON object in valid UTF-8 without a
// byte order mark.
func jsonObject(raw []byte) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if !utf8.Valid(raw) || json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}
