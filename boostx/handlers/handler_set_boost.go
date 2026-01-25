package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// SetBoostHandler handles POST /setBoost requests.
type SetBoostHandler struct {
	keys  KeyStore
	store BetStore
}

// NewSetBoostHandler creates a new SetBoostHandler.
func NewSetBoostHandler(store BetStore, keys KeyStore) *SetBoostHandler {
	return &SetBoostHandler{keys: keys, store: store}
}

// setBoostRequest is the request body for POST /setBoost.
type setBoostRequest struct {
	BoostJWT string `json:"boostJWT"`
}

// ServeHTTP receives and validates boost updates from BoostX.
func (h *SetBoostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req setBoostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Extract claims without verification to get key lookup params
	partner, user, bet, err := tokens.ExtractBoostClaims(req.BoostJWT)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid boost token")
		return
	}

	boostPubKey, err := h.keys.BoostPublicKey(r.Context(), partner, user, bet)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get boost key")
		return
	}

	gamepassPubKey, err := h.keys.GamePassPublicKey(r.Context(), partner, user, bet)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get gamepass key")
		return
	}

	boost, err := tokens.ParseBoostToken(req.BoostJWT, boostPubKey, gamepassPubKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid boost token")
		return
	}

	if err := h.store.SetBoost(r.Context(), boost); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to set boost")
		return
	}

	writeJSON(w, http.StatusOK, struct{}{})
}
