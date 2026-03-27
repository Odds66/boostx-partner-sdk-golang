package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// CheckBetHandler handles POST /check-bet requests.
type CheckBetHandler struct {
	keys  KeyStore
	store BetStoreChecker
}

// NewCheckBetHandler creates a new CheckBetHandler.
func NewCheckBetHandler(store BetStoreChecker, keys KeyStore) *CheckBetHandler {
	return &CheckBetHandler{keys: keys, store: store}
}

// checkBetRequest is the request body for POST /check-bet.
type checkBetRequest struct {
	CheckBetJWT string `json:"checkbetJWT"`
}

// checkBetResponse is the response body for POST /check-bet.
type checkBetResponse struct {
	Active bool `json:"active"`
}

// ServeHTTP validates checkbetJWT and checks if bet is active.
func (h *CheckBetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req checkBetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Extract claims without verification to get key lookup params
	partner, user, bet, err := tokens.ExtractCheckBetClaims(req.CheckBetJWT)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid checkbet token")
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

	checkBet, err := tokens.ParseCheckBetToken(req.CheckBetJWT, boostxPubKey, partnerPubKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid checkbet token")
		return
	}

	active, err := h.store.CheckBet(r.Context(), &checkBet.GID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check bet")
		return
	}

	writeJSON(w, http.StatusOK, resultResponse{Result: checkBetResponse{Active: active}})
}
