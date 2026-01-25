package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// GetBetHandler handles POST /getBet requests.
type GetBetHandler struct {
	keys  KeyStore
	store BetStore
}

// NewGetBetHandler creates a new GetBetHandler.
func NewGetBetHandler(store BetStore, keys KeyStore) *GetBetHandler {
	return &GetBetHandler{keys: keys, store: store}
}

// getBetRequest is the request body for POST /getBet.
type getBetRequest struct {
	IdentityJWT string `json:"identityJWT"`
}

// ServeHTTP returns bet information and result.
func (h *GetBetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req getBetRequest
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

	betInfo, err := h.store.GetBet(r.Context(), identity)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get bet")
		return
	}

	if betInfo == nil {
		writeError(w, http.StatusNotFound, "bet not found")
		return
	}

	writeJSON(w, http.StatusOK, betInfo)
}
