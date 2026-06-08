package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// VerifyKeysHandler handles POST /verify-keys requests.
type VerifyKeysHandler struct {
	keys KeyStore
}

// NewVerifyKeysHandler creates a new VerifyKeysHandler.
func NewVerifyKeysHandler(keys KeyStore) *VerifyKeysHandler {
	return &VerifyKeysHandler{keys: keys}
}

type verifyKeysRequest struct {
	VerifyKeysJWT string `json:"verifyKeysJWT"`
}

type verifyKeysResult struct {
	ResponseJWT string `json:"responseJWT"`
}

// ServeHTTP performs the signed round-trip that confirms both sides hold the
// correct counterpart keys.
func (h *VerifyKeysHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req verifyKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	partner, err := tokens.ExtractVerifyKeysRequestPartner(req.VerifyKeysJWT)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid verifyKeysJWT: "+tokens.VerifyKeysReasonShape)
		return
	}

	ctx := r.Context()
	boostxPubKey, err := h.keys.BoostxPublicKey(ctx, partner)
	if err != nil {
		writeKeyError(w, err, "boostx key")
		return
	}

	verified, err := tokens.ParseVerifyKeysRequestToken(req.VerifyKeysJWT, boostxPubKey, partner, 0)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid verifyKeysJWT: "+tokens.VerifyKeysReason(err))
		return
	}

	partnerPrivKey, err := h.keys.PartnerPrivateKey(ctx, partner)
	if err != nil {
		writeKeyError(w, err, "partner private key")
		return
	}

	responseJWT, err := tokens.CreateVerifyKeysResponseToken(partnerPrivKey, partner, verified.Nonce)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign response")
		return
	}

	writeJSON(w, http.StatusOK, resultResponse{Result: verifyKeysResult{ResponseJWT: responseJWT}})
}
