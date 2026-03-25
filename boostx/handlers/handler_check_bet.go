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
	CheckBetJWT string `json:"checkbetJWT"`
}

// checkBetResponse is the response body for POST /checkBet.
type checkBetResponse struct {
	Active bool `json:"active"`
}

// ServeHTTP validates checkbetJWT and checks if bet is active.
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
	partner, user, bet, err := tokens.ExtractCheckBetClaims(req.CheckBetJWT)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid checkbet token")
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

	checkBet, err := tokens.ParseCheckBetToken(req.CheckBetJWT, boosterPubKey, partnerPubKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid checkbet token")
		return
	}

	active, err := h.store.CheckBet(r.Context(), &checkBet.GID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check bet")
		return
	}

	writeJSON(w, http.StatusOK, checkBetResponse{Active: active})
}
