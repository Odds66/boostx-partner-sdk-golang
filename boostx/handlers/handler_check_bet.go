package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// CheckBetHandler handles POST /checkBet requests.
type CheckBetHandler struct {
	keys  KeyStore
	store BetStoreChecker
}

// NewCheckBetHandler creates a new CheckBetHandler.
func NewCheckBetHandler(store BetStoreChecker, keys KeyStore) *CheckBetHandler {
	return &CheckBetHandler{keys: keys, store: store}
}

// checkBetRequest is the request body for POST /checkBet.
type checkBetRequest struct {
	IdentityJWT string `json:"identityJWT"`
}

// checkBetResponse is the response body for POST /checkBet.
type checkBetResponse struct {
	Active bool `json:"active"`
}

// ServeHTTP validates identityJWT and checks if bet is active.
func (h *CheckBetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req checkBetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Extract claims without verification to get key lookup params
	unverified, err := tokens.ExtractIdentityClaims(req.IdentityJWT)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid identity token")
		return
	}

	gamepassPubKey, err := h.keys.GamePassPublicKey(r.Context(), unverified.Partner, unverified.User, unverified.Bet)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get gamepass key")
		return
	}

	identity, err := tokens.ParseIdentityJWT(req.IdentityJWT, gamepassPubKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid identity token")
		return
	}

	active, err := h.store.CheckBet(r.Context(), identity)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check bet")
		return
	}

	writeJSON(w, http.StatusOK, checkBetResponse{Active: active})
}
