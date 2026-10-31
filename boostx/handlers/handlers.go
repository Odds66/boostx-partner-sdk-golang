package handlers

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
)

// maxRequestBodySize limits request body to 64KB.
const maxRequestBodySize = 64 * 1024

// errorResponse is the standard error response format.
type errorResponse struct {
	Error string `json:"error"`
}

// resultResponse wraps a response payload in the {"result": ...} envelope
// expected by the BoostX backend.
type resultResponse struct {
	Result any `json:"result"`
}

// okResult is the success payload for endpoints that have no domain-specific data.
type okResult struct {
	OK bool `json:"ok"`
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{Error: message})
}

// writeKeyError maps a key-store lookup failure to a response: an unknown
// partner_id is a client error (400) naming the id the request carried, so a
// partner registered under a different id can see the mismatch; anything else
// is a backend failure (500).
func writeKeyError(w http.ResponseWriter, err error, what, partner string) {
	if errors.Is(err, keys.ErrUnknownPartner) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown partner %q", partner))
		return
	}
	writeError(w, http.StatusInternalServerError, "failed to get "+what)
}

// partnerPublicKeys returns the keys that verify a GID: every key when
// keyStore implements PartnerPublicKeysStore, else its one PartnerPublicKey.
func partnerPublicKeys(ctx context.Context, keyStore KeyStore, partner string) ([]*ecdsa.PublicKey, error) {
	if s, ok := keyStore.(PartnerPublicKeysStore); ok {
		return s.PartnerPublicKeys(ctx, partner)
	}
	k, err := keyStore.PartnerPublicKey(ctx, partner)
	if err != nil {
		return nil, err
	}
	return []*ecdsa.PublicKey{k}, nil
}

// mustNotBeNil panics on an untyped nil constructor argument, as
// http.ServeMux.Handle does on a nil handler.
func mustNotBeNil(v any, what string) {
	if v == nil {
		panic("boostx: nil " + what)
	}
}

// Mount registers the partner-side BoostX handlers on mux under prefix:
// POST /set-boost and POST /verify-keys always; POST /check-bet when betStore
// implements BetStoreChecker. prefix is the path of your API URL, starting
// with "/" (or empty); a trailing slash is trimmed. Panics if betStore or
// keyStore is nil.
func Mount(mux *http.ServeMux, prefix string, betStore BetStoreUpdater, keyStore KeyStore) {
	prefix = strings.TrimSuffix(prefix, "/")
	if cbs, ok := betStore.(BetStoreChecker); ok {
		mux.Handle("POST "+prefix+"/check-bet", NewCheckBetHandler(cbs, keyStore))
	}
	mux.Handle("POST "+prefix+"/set-boost", NewSetBoostHandler(betStore, keyStore))
	mux.Handle("POST "+prefix+"/verify-keys", NewVerifyKeysHandler(keyStore))
}
