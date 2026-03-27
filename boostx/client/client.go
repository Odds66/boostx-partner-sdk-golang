// Package client provides an HTTP client for outbound BoostX Partner API calls.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DefaultBaseURL is the production BoostX partners S2S API base URL.
const DefaultBaseURL = "https://partners-s2s.boostx.cloud"

// apiResponse is the standard envelope returned by the BoostX API.
type apiResponse struct {
	Result json.RawMessage `json:"result"`
	Error  string          `json:"error"`
}

// APIError is returned when the API responds with a non-success status code
// or the response body contains an "error" envelope.
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

// WithBaseURL overrides the default base URL.
func WithBaseURL(url string) Option {
	return func(c *Client) { c.baseURL = url }
}

// WithHTTPClient provides a custom http.Client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// New creates a Client with the given key store and options.
func New(keys KeyStore, opts ...Option) *Client {
	c := &Client{
		keys:       keys,
		baseURL:    DefaultBaseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// doAPIRequest sends a POST request and parses the standard response envelope.
// On success, it unmarshals the "result" field into dest (pass nil to discard).
// On error, it returns an *APIError.
func (c *Client) doAPIRequest(ctx context.Context, path string, body, dest any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var envelope apiResponse
		if err := json.NewDecoder(resp.Body).Decode(&envelope); err == nil && envelope.Error != "" {
			return &APIError{StatusCode: resp.StatusCode, Message: envelope.Error}
		}
		return &APIError{StatusCode: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	}

	if dest == nil {
		return nil
	}

	var envelope apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if envelope.Error != "" {
		return &APIError{StatusCode: resp.StatusCode, Message: envelope.Error}
	}
	if len(envelope.Result) > 0 {
		if err := json.Unmarshal(envelope.Result, dest); err != nil {
			return fmt.Errorf("unmarshal result: %w", err)
		}
	}
	return nil
}
