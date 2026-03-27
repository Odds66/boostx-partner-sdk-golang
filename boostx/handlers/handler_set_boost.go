package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// SetBoostHandler handles POST /set-boost requests.
type SetBoostHandler struct {
	keys  KeyStore
	store BetStoreUpdater
}

// NewSetBoostHandler creates a new SetBoostHandler.
func NewSetBoostHandler(store BetStoreUpdater, keys KeyStore) *SetBoostHandler {
	return &SetBoostHandler{keys: keys, store: store}
}

// setBoostRequest is the request body for POST /set-boost.
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

	boostxPubKey, err := h.keys.BoostxPublicKey(r.Context(), partner, user, bet)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get boostx key")
		return
	}

	partnerPubKey, err := h.keys.PartnerPublicKey(r.Context(), partner, user, bet)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get partner key")
		return
	}

	booster, err := tokens.ParseBoosterToken(req.BoosterJWT, boostxPubKey, partnerPubKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid booster token")
		return
	}

	if err := h.store.SetBoost(r.Context(), booster); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to set boost")
		return
	}

	writeJSON(w, http.StatusOK, resultResponse{Result: okResult{OK: true}})
}
