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

// Mount registers all handlers on the given mux at the specified prefix.
// Example: Mount(mux, "/api/boostx", keys, store) registers /api/boostx/checkBet, etc.
func Mount(mux *http.ServeMux, prefix string, betStore BetStore, keyStore KeyStore) {
	prefix = strings.TrimSuffix(prefix, "/")
	mux.Handle(prefix+"/checkBet", NewCheckBetHandler(betStore, keyStore))
	mux.Handle(prefix+"/getBet", NewGetBetHandler(betStore, keyStore))
	mux.Handle(prefix+"/setBoost", NewSetBoostHandler(betStore, keyStore))
}
