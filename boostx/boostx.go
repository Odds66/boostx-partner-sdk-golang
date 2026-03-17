// Package boostx provides the BoostX Partner SDK for Go.
//
// This package re-exports types and functions from subpackages for convenience,
// allowing partners to import only this package for most use cases.
package boostx

import (
	"crypto/ecdsa"
	"net/http"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/handlers"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// Token types for GamePass, Boost, and Identity JWT payloads.
type (
	Identity         = tokens.Identity
	GamePass         = tokens.GamePass
	GamePassParams   = tokens.GamePassParams
	Boost            = tokens.Boost
	RegisteredClaims = tokens.RegisteredClaims
)

// Handler interfaces for key and bet storage.
type (
	KeyStore        = handlers.KeyStore
	BetStoreUpdater = handlers.BetStoreUpdater
	BetStoreChecker = handlers.BetStoreChecker
)

// Sentinel errors for token parsing and validation.
var (
	ErrInvalidPrivateKey = tokens.ErrInvalidPrivateKey
	ErrInvalidPublicKey  = tokens.ErrInvalidPublicKey
	ErrInvalidGamePass   = tokens.ErrInvalidGamePass
	ErrInvalidBoost      = tokens.ErrInvalidBoost
	ErrInvalidIdentity   = tokens.ErrInvalidIdentity
	ErrInvalidSignature  = tokens.ErrInvalidSignature
	ErrMissingClaim      = tokens.ErrMissingClaim
	ErrInvalidClaim      = tokens.ErrInvalidClaim
)

// MountHandlers registers handlers on mux at prefix. The /setBoost endpoint is
// always registered. The /checkBet endpoint is registered only if store implements
// BetStoreChecker. Uses static keys for token verification. Returns error if either key is nil.
func MountHandlers(mux *http.ServeMux, prefix string, store BetStoreUpdater, gamepassPubKey, boostPubKey *ecdsa.PublicKey) error {
	keyStore, err := keys.NewStaticKeyStore(gamepassPubKey, boostPubKey)
	if err != nil {
		return err
	}
	handlers.Mount(mux, prefix, store, keyStore)
	return nil
}

// MountHandlersWithKeyStorage mounts handlers with a custom KeyStore for multi-tenant scenarios.
func MountHandlersWithKeyStorage(mux *http.ServeMux, prefix string, betStore BetStoreUpdater, keyStore KeyStore) {
	handlers.Mount(mux, prefix, betStore, keyStore)
}

// CreateGamePassToken creates a signed GamePass JWT for testing purposes.
func CreateGamePassToken(privateKey *ecdsa.PrivateKey, params GamePassParams) (string, error) {
	return tokens.CreateGamePassToken(privateKey, params)
}
