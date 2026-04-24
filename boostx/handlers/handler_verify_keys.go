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

	partner, err := tokens.ExtractVerifyKeysAudience(req.VerifyKeysJWT)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid verifyKeysJWT: "+tokens.VerifyKeysReasonShape)
		return
	}

	// verify-keys has no GID, so there is no user/bet context — multi-tenant
	// implementations should key only on partner.
	ctx := r.Context()
	boostxPubKey, err := h.keys.BoostxPublicKey(ctx, partner, "", "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get boostx key")
		return
	}

	verified, err := tokens.ParseVerifyKeysToken(req.VerifyKeysJWT, boostxPubKey, tokens.BoostxIdentity, partner, 0)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid verifyKeysJWT: "+tokens.VerifyKeysReason(err))
		return
	}

	partnerPrivKey, err := h.keys.PartnerPrivateKey(ctx, partner, "", "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get partner private key")
		return
	}

	responseJWT, err := tokens.CreateVerifyKeysToken(partnerPrivKey, partner, tokens.BoostxIdentity, verified.Nonce)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign response")
		return
	}

	writeJSON(w, http.StatusOK, resultResponse{Result: verifyKeysResult{ResponseJWT: responseJWT}})
}
