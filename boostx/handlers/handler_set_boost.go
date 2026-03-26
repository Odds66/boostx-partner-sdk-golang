package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// SetBoostHandler handles POST /setBoost requests.
type SetBoostHandler struct {
	keys  KeyStore
	store BetStoreUpdater
}

// NewSetBoostHandler creates a new SetBoostHandler.
func NewSetBoostHandler(store BetStoreUpdater, keys KeyStore) *SetBoostHandler {
	return &SetBoostHandler{keys: keys, store: store}
}

// setBoostRequest is the request body for POST /setBoost.
type setBoostRequest struct {
	BoosterJWT string `json:"boosterJWT"`
}

// ServeHTTP receives and validates boost updates from BoostX.
func (h *SetBoostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req setBoostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Extract claims without verification to get key lookup params
	partner, user, bet, err := tokens.ExtractBoosterClaims(req.BoosterJWT)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid booster token")
		return
	}

	boosterPubKey, err := h.keys.BoosterPublicKey(r.Context(), partner, user, bet)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get booster key")
		return
	}

	// GamePass key is the partner's key — used to verify the GID signature
	partnerPubKey, err := h.keys.GamePassPublicKey(r.Context(), partner, user, bet)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get gamepass key")
		return
	}

	booster, err := tokens.ParseBoosterToken(req.BoosterJWT, boosterPubKey, partnerPubKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid booster token")
		return
	}

	if err := h.store.SetBoost(r.Context(), booster); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to set boost")
		return
	}

	w.WriteHeader(http.StatusOK)
}
