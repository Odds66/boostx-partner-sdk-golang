// Package boostx provides the BoostX Partner SDK for Go.
//
// This package re-exports types and functions from subpackages for convenience,
// allowing partners to import only this package for most use cases.
package boostx

import (
	"crypto/ecdsa"
	"net/http"
	"time"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/client"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/handlers"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// Key management types for key storage, signing, and verification.
type (
	ClientKeyStore        = client.KeyStore
	HandlersKeyStore      = handlers.KeyStore
	StaticKeyStore        = keys.StaticKeyStore
	StaticPublicKeyStore  = keys.StaticPublicKeyStore
	StaticPrivateKeyStore = keys.StaticPrivateKeyStore
)

// Token types for GID, GamePass, Booster, CheckBet, Settlement, VerifyKeys, and Money.
type (
	GID              = tokens.GID
	GamePass         = tokens.GamePass
	GamePassParams   = tokens.GamePassParams
	Booster          = tokens.Booster
	CheckBet         = tokens.CheckBet
	Settlement       = tokens.Settlement
	SettlementParams = tokens.SettlementParams
	VerifyKeys       = tokens.VerifyKeys
	Money            = tokens.Money
	RegisteredClaims = tokens.RegisteredClaims
)

// VerifyKeys protocol constants.
const (
	BoostxIdentity = tokens.BoostxIdentity

	VerifyKeysReasonShape       = tokens.VerifyKeysReasonShape
	VerifyKeysReasonIssAud      = tokens.VerifyKeysReasonIssAud
	VerifyKeysReasonStale       = tokens.VerifyKeysReasonStale
	VerifyKeysReasonNonceFormat = tokens.VerifyKeysReasonNonceFormat
	VerifyKeysReasonSignature   = tokens.VerifyKeysReasonSignature
)

// VerifyKeysReason maps a ParseVerifyKeysToken error to its protocol reason string.
func VerifyKeysReason(err error) string {
	return tokens.VerifyKeysReason(err)
}

// Handlers and client types for the HTTP layer.
type (
	BetStoreUpdater = handlers.BetStoreUpdater
	BetStoreChecker = handlers.BetStoreChecker
	APIError        = client.APIError
)

// Sentinel errors for token parsing and validation.
var (
	ErrInvalidPrivateKey = tokens.ErrInvalidPrivateKey
	ErrInvalidPublicKey  = tokens.ErrInvalidPublicKey
	ErrInvalidGamePass   = tokens.ErrInvalidGamePass
	ErrInvalidBooster    = tokens.ErrInvalidBooster
	ErrInvalidCheckBet   = tokens.ErrInvalidCheckBet
	ErrInvalidSettlement = tokens.ErrInvalidSettlement
	ErrInvalidVerifyKeys = tokens.ErrInvalidVerifyKeys
	ErrVerifyKeysShape   = tokens.ErrVerifyKeysShape
	ErrVerifyKeysIssAud  = tokens.ErrVerifyKeysIssAud
	ErrVerifyKeysStale   = tokens.ErrVerifyKeysStale
	ErrVerifyKeysNonce   = tokens.ErrVerifyKeysNonce
	ErrInvalidGID        = tokens.ErrInvalidGID
	ErrInvalidSignature  = tokens.ErrInvalidSignature
	ErrMissingClaim      = tokens.ErrMissingClaim
	ErrInvalidClaim      = tokens.ErrInvalidClaim
)

// MountHandlers mounts the partner-side BoostX handlers on mux under prefix:
// POST /set-boost and POST /verify-keys always; POST /check-bet when store
// implements BetStoreChecker.
//
// Keys: partnerPubKey verifies GID signatures on inbound tokens; boostxPubKey
// verifies Booster/CheckBet/VerifyKeys request JWTs; partnerPrivKey signs the
// /verify-keys response. All three are required — returns an error if any is nil.
func MountHandlers(
	mux *http.ServeMux,
	prefix string,
	store BetStoreUpdater,
	partnerPubKey, boostxPubKey *ecdsa.PublicKey,
	partnerPrivKey *ecdsa.PrivateKey,
) error {
	keyStore, err := keys.NewStaticKeyStore(partnerPubKey, boostxPubKey, partnerPrivKey)
	if err != nil {
		return err
	}
	handlers.Mount(mux, prefix, store, keyStore)
	return nil
}

// MountHandlersWithKeyStorage mounts handlers with a custom HandlersKeyStore for multi-tenant scenarios.
func MountHandlersWithKeyStorage(mux *http.ServeMux, prefix string, betStore BetStoreUpdater, keyStore HandlersKeyStore) {
	handlers.Mount(mux, prefix, betStore, keyStore)
}

// CreateVerifyKeysToken creates a signed verify-keys JWT with the given iss/aud/nonce.
func CreateVerifyKeysToken(privateKey *ecdsa.PrivateKey, issuer, audience string, nonce int32) (string, error) {
	return tokens.CreateVerifyKeysToken(privateKey, issuer, audience, nonce)
}

// ParseVerifyKeysToken parses and verifies a verify-keys JWT.
func ParseVerifyKeysToken(
	token string,
	publicKey *ecdsa.PublicKey,
	expectedIssuer, expectedAudience string,
	maxSkew time.Duration,
) (*VerifyKeys, error) {
	return tokens.ParseVerifyKeysToken(token, publicKey, expectedIssuer, expectedAudience, maxSkew)
}

// NewStaticPrivateKeyStore creates a StaticPrivateKeyStore with the given key.
func NewStaticPrivateKeyStore(key *ecdsa.PrivateKey) (*StaticPrivateKeyStore, error) {
	return keys.NewStaticPrivateKeyStore(key)
}

// NewClient creates a new BoostX API client for outbound calls.
func NewClient(keys ClientKeyStore, opts ...client.Option) *client.Client {
	return client.New(keys, opts...)
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
