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
// The /setBoost endpoint is always registered.
// The /checkBet endpoint is registered only if betStore implements BetStoreChecker.
func Mount(mux *http.ServeMux, prefix string, betStore BetStoreUpdater, keyStore KeyStore) {
	prefix = strings.TrimSuffix(prefix, "/")
	if cbs, ok := betStore.(BetStoreChecker); ok {
		mux.Handle(prefix+"/checkBet", NewCheckBetHandler(cbs, keyStore))
	}
	mux.Handle(prefix+"/setBoost", NewSetBoostHandler(betStore, keyStore))
}
