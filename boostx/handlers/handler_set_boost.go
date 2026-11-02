package handlers

import (
	"errors"
	"net/http"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// SetBoostHandler handles POST /set-boost requests.
type SetBoostHandler struct {
	keys  KeyStore
	store BetStoreUpdater
}

// NewSetBoostHandler creates a new SetBoostHandler. Panics if store or keyStore is nil.
func NewSetBoostHandler(store BetStoreUpdater, keyStore KeyStore) *SetBoostHandler {
	mustNotBeNil(store, "bet store")
	mustNotBeNil(keyStore, "key store")
	return &SetBoostHandler{keys: keyStore, store: store}
}

// ServeHTTP receives and validates boost updates from BoostX.
func (h *SetBoostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !isPost(w, r) {
		return
	}
	token, ok := readToken(w, r, "boosterJWT")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Extract claims without verification to get key lookup params
	partner, err := tokens.ExtractBoosterPartner(token)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid booster token")
		return
	}

	boostxPubKey, err := h.keys.BoostxPublicKey(r.Context(), partner)
	if err != nil {
		writeKeyError(w, err, "boostx key", partner)
		return
	}

	partnerPubKeys, err := partnerPublicKeys(r.Context(), h.keys, partner)
	if err != nil {
		writeKeyError(w, err, "partner key", partner)
		return
	}

	booster, err := tokens.ParseBoosterTokenWithKeys(token, boostxPubKey, partnerPubKeys)
	if err != nil {
		if errors.Is(err, tokens.ErrInvalidPublicKey) {
			writeError(w, http.StatusInternalServerError, "failed to verify token")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid booster token")
		return
	}

	if err := h.store.SetBoost(r.Context(), booster); err != nil {
		if errors.Is(err, ErrRoundRejected) {
			writeError(w, http.StatusBadRequest, "round rejected")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to set boost")
		return
	}

	writeJSON(w, http.StatusOK, resultResponse{Result: okResult{OK: true}})
}
