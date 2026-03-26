// Package boostx provides the BoostX Partner SDK for Go.
//
// This package re-exports types and functions from subpackages for convenience,
// allowing partners to import only this package for most use cases.
package boostx

import (
	"crypto/ecdsa"
	"net/http"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/client"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/handlers"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// Token types for GID, GamePass, Booster, CheckBet, Settlement, and Money.
type (
	GID              = tokens.GID
	GamePass         = tokens.GamePass
	GamePassParams   = tokens.GamePassParams
	Booster          = tokens.Booster
	CheckBet         = tokens.CheckBet
	Settlement       = tokens.Settlement
	SettlementParams = tokens.SettlementParams
	Money            = tokens.Money
	RegisteredClaims = tokens.RegisteredClaims
)

// APIError is returned when the BoostX API responds with an error.
type APIError = client.APIError

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
	ErrInvalidBooster    = tokens.ErrInvalidBooster
	ErrInvalidCheckBet   = tokens.ErrInvalidCheckBet
	ErrInvalidSettlement = tokens.ErrInvalidSettlement
	ErrInvalidGID        = tokens.ErrInvalidGID
	ErrInvalidSignature  = tokens.ErrInvalidSignature
	ErrMissingClaim      = tokens.ErrMissingClaim
	ErrInvalidClaim      = tokens.ErrInvalidClaim
)

// MountHandlers registers handlers on mux at prefix. The /setBoost endpoint is
// always registered. The /checkBet endpoint is registered only if store implements
// BetStoreChecker. Uses static keys for token verification. Returns error if either key is nil.
func MountHandlers(mux *http.ServeMux, prefix string, store BetStoreUpdater, gamepassPubKey, boosterPubKey *ecdsa.PublicKey) error {
	keyStore, err := keys.NewStaticKeyStore(gamepassPubKey, boosterPubKey)
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

// NewClient creates a new BoostX API client for outbound calls.
func NewClient(opts ...client.Option) *client.Client {
	return client.New(opts...)
}

// CreateGamePassToken creates a signed GamePass JWT for testing purposes.
func CreateGamePassToken(privateKey *ecdsa.PrivateKey, params GamePassParams) (string, error) {
	return tokens.CreateGamePassToken(privateKey, params)
}

// CreateSettlementToken creates a signed Settlement JWT.
func CreateSettlementToken(privateKey *ecdsa.PrivateKey, params SettlementParams) (string, error) {
	return tokens.CreateSettlementToken(privateKey, params)
}

// BuildGID creates a signed GID struct.
func BuildGID(partner, user, bet string, privateKey *ecdsa.PrivateKey) (*GID, error) {
	return tokens.BuildGID(partner, user, bet, privateKey)
}

// Key loading utilities — delegates to boostx/keys package.

// LoadPrivateKeyFromFile reads and parses an ECDSA P-256 private key from a file.
func LoadPrivateKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	return keys.LoadPrivateKeyFromFile(path)
}

// LoadPrivateKeyFromPEM parses an ECDSA P-256 private key from PEM-encoded data.
func LoadPrivateKeyFromPEM(pemData []byte) (*ecdsa.PrivateKey, error) {
	return keys.LoadPrivateKeyFromPEM(pemData)
}

// LoadPublicKeyFromFile reads and parses an ECDSA P-256 public key from a file.
func LoadPublicKeyFromFile(path string) (*ecdsa.PublicKey, error) {
	return keys.LoadPublicKeyFromFile(path)
}

// LoadPublicKeyFromPEM parses an ECDSA P-256 public key from PEM-encoded data.
func LoadPublicKeyFromPEM(pemData []byte) (*ecdsa.PublicKey, error) {
	return keys.LoadPublicKeyFromPEM(pemData)
}
