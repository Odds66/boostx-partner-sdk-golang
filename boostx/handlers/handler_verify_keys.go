package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
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
		if errors.Is(err, keys.ErrUnknownPartner) {
			writeError(w, http.StatusBadRequest, unservedPartnerReason(partner))
			return
		}
		writeKeyError(w, err, "boostx key", partner)
		return
	}

	verified, err := tokens.ParseVerifyKeysRequestToken(req.VerifyKeysJWT, boostxPubKey, partner, 0)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid verifyKeysJWT: "+tokens.VerifyKeysReason(err))
		return
	}

	partnerPrivKey, err := h.keys.PartnerPrivateKey(ctx, partner)
	if err != nil {
		if errors.Is(err, keys.ErrUnknownPartner) {
			writeError(w, http.StatusBadRequest, unservedPartnerReason(partner))
			return
		}
		writeKeyError(w, err, "partner private key", partner)
		return
	}

	responseJWT, err := tokens.CreateVerifyKeysResponseToken(partnerPrivKey, partner, verified.Nonce)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign response")
		return
	}

	writeJSON(w, http.StatusOK, resultResponse{Result: verifyKeysResult{ResponseJWT: responseJWT}})
}

// unservedPartnerReason is the error body for a verify-keys request whose aud
// names a partner this deployment does not serve. On the wire that is an
// "iss-aud" failure — the id mismatch reason — not a key-lookup failure, so the
// BoostX diagnostic attributes it to the partner-id configuration rather than
// to keys. The parenthetical is for humans and is ignored by reason parsing.
func unservedPartnerReason(partner string) string {
	return fmt.Sprintf("invalid verifyKeysJWT: %s (unknown partner %q)", tokens.VerifyKeysReasonIssAud, partner)
}
