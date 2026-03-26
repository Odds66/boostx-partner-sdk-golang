package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
)

// maxRequestBodySize limits request body to 64KB.
const maxRequestBodySize = 64 * 1024

// errorResponse is the standard error response format.
type errorResponse struct {
	Error string `json:"error"`
}

// resultResponse wraps a response payload in the {"result": ...} envelope
// expected by the BoostX backend.
type resultResponse struct {
	Result any `json:"result"`
}

// okResult is the success payload for endpoints that have no domain-specific data.
type okResult struct {
	OK bool `json:"ok"`
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}

// Mount registers handlers on the given mux at the specified prefix.
// The /set-boost endpoint is always registered.
// The /check-bet endpoint is registered only if betStore implements BetStoreChecker.
func Mount(mux *http.ServeMux, prefix string, betStore BetStoreUpdater, keyStore KeyStore) {
	prefix = strings.TrimSuffix(prefix, "/")
	if cbs, ok := betStore.(BetStoreChecker); ok {
		mux.Handle("POST "+prefix+"/check-bet", NewCheckBetHandler(cbs, keyStore))
	}
	mux.Handle("POST "+prefix+"/set-boost", NewSetBoostHandler(betStore, keyStore))
}
