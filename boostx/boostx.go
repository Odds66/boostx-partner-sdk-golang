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

// Key management types. MemoryKeyStore holds each partner_id's keys in memory
// and satisfies HandlersKeyStore and ClientKeyStore; for keys that live outside
// the process (database, secret manager), implement those interfaces directly.
type (
	ClientKeyStore   = client.KeyStore
	HandlersKeyStore = handlers.KeyStore
	MemoryKeyStore   = keys.MemoryKeyStore
)

// Token types: GID, the inbound result structs (Booster, CheckBet, VerifyKeys
// request/response), and the outbound *Params builders.
type (
	GID                = tokens.GID
	GamePassParams     = tokens.GamePassParams
	Booster            = tokens.Booster
	CheckBet           = tokens.CheckBet
	SettlementParams   = tokens.SettlementParams
	VerifyKeysRequest  = tokens.VerifyKeysRequest
	VerifyKeysResponse = tokens.VerifyKeysResponse
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

// VerifyKeysReason maps a verify-keys parse error to its protocol reason string.
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
// implements BetStoreChecker. keyStore supplies each partner_id's keys — use a
// MemoryKeyStore, or your own HandlersKeyStore implementation for external keys.
func MountHandlers(mux *http.ServeMux, prefix string, store BetStoreUpdater, keyStore HandlersKeyStore) {
	handlers.Mount(mux, prefix, store, keyStore)
}

// The constructors below return each partner-side endpoint as an http.Handler,
// for routers other than *http.ServeMux (gin, echo, chi, …) where MountHandlers
// does not apply. Register them as POST routes under your chosen prefix —
// MountHandlers is equivalent to registering POST <prefix>/set-boost,
// POST <prefix>/verify-keys, and (when the store implements BetStoreChecker)
// POST <prefix>/check-bet.

// NewSetBoostHandler returns the POST /set-boost handler.
func NewSetBoostHandler(store BetStoreUpdater, keyStore HandlersKeyStore) http.Handler {
	return handlers.NewSetBoostHandler(store, keyStore)
}

// NewVerifyKeysHandler returns the POST /verify-keys handler.
func NewVerifyKeysHandler(keyStore HandlersKeyStore) http.Handler {
	return handlers.NewVerifyKeysHandler(keyStore)
}

// NewCheckBetHandler returns the POST /check-bet handler. The store must
// implement BetStoreChecker; mount this only if you accept check-bet requests.
func NewCheckBetHandler(store BetStoreChecker, keyStore HandlersKeyStore) http.Handler {
	return handlers.NewCheckBetHandler(store, keyStore)
}

// CreateVerifyKeysRequestToken signs the BoostX → partner verify-keys request (iss="boostx", aud=partnerID).
func CreateVerifyKeysRequestToken(boostxPriv *ecdsa.PrivateKey, partnerID string, nonce int32) (string, error) {
	return tokens.CreateVerifyKeysRequestToken(boostxPriv, partnerID, nonce)
}

// ParseVerifyKeysRequestToken verifies a BoostX → partner verify-keys request (expects iss="boostx", aud=partnerID).
func ParseVerifyKeysRequestToken(
	token string,
	boostxPub *ecdsa.PublicKey,
	partnerID string,
	maxSkew time.Duration,
) (*VerifyKeysRequest, error) {
	return tokens.ParseVerifyKeysRequestToken(token, boostxPub, partnerID, maxSkew)
}

// CreateVerifyKeysResponseToken signs the partner → BoostX verify-keys response (iss=partnerID, aud="boostx").
func CreateVerifyKeysResponseToken(partnerPriv *ecdsa.PrivateKey, partnerID string, nonce int32) (string, error) {
	return tokens.CreateVerifyKeysResponseToken(partnerPriv, partnerID, nonce)
}

// ParseVerifyKeysResponseToken verifies a partner → BoostX verify-keys response (expects iss=partnerID, aud="boostx").
func ParseVerifyKeysResponseToken(
	token string,
	partnerPub *ecdsa.PublicKey,
	partnerID string,
	maxSkew time.Duration,
) (*VerifyKeysResponse, error) {
	return tokens.ParseVerifyKeysResponseToken(token, partnerPub, partnerID, maxSkew)
}

// ExtractVerifyKeysRequestPartner returns the unverified partner ID (the "aud"
// claim) from a BoostX → partner verify-keys request, for key lookup.
// WARNING: Use only for key lookup. Always verify with ParseVerifyKeysRequestToken afterwards.
func ExtractVerifyKeysRequestPartner(token string) (string, error) {
	return tokens.ExtractVerifyKeysRequestPartner(token)
}

// Inbound token parsing — for partners who handle /set-boost and /check-bet
// without the SDK's handlers (e.g. on a custom server). The verify-keys
// request parser above completes the inbound set.

// ParseBoosterToken verifies an inbound /set-boost Booster JWT, checking both
// the BoostX JWT signature (boostxPub) and the embedded partner GID signature
// (partnerPub).
func ParseBoosterToken(boosterJWT string, boostxPub, partnerPub *ecdsa.PublicKey) (*Booster, error) {
	return tokens.ParseBoosterToken(boosterJWT, boostxPub, partnerPub)
}

// ExtractBoosterPartner returns the partner_id from an inbound Booster JWT
// without verifying it, for key lookup.
// WARNING: Use only for key lookup. Always verify with ParseBoosterToken afterwards.
func ExtractBoosterPartner(boosterJWT string) (string, error) {
	return tokens.ExtractBoosterPartner(boosterJWT)
}

// ParseCheckBetToken verifies an inbound /check-bet CheckBet JWT, checking both
// the BoostX JWT signature (boostxPub) and the embedded partner GID signature
// (partnerPub).
func ParseCheckBetToken(checkBetJWT string, boostxPub, partnerPub *ecdsa.PublicKey) (*CheckBet, error) {
	return tokens.ParseCheckBetToken(checkBetJWT, boostxPub, partnerPub)
}

// ExtractCheckBetPartner returns the partner_id from an inbound CheckBet JWT
// without verifying it, for key lookup.
// WARNING: Use only for key lookup. Always verify with ParseCheckBetToken afterwards.
func ExtractCheckBetPartner(checkBetJWT string) (string, error) {
	return tokens.ExtractCheckBetPartner(checkBetJWT)
}

// NewMemoryKeyStore creates an empty in-memory multi-tenant MemoryKeyStore.
// Register each partner_id's keys, then pass it to MountHandlers, the handler
// constructors, or NewClient.
func NewMemoryKeyStore() *MemoryKeyStore {
	return keys.NewMemoryKeyStore()
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
