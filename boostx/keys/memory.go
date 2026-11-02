package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// ErrUnknownPartner is returned (wrapped) by a MemoryKeyStore lookup when no
// keys are registered for the partner_id. The mounted handlers map it to a 400.
var ErrUnknownPartner = errors.New("unknown partner")

// keySet is a partner's stored keys. Any field may be nil when the partner only
// fills some roles (sign-only or verify-only); each accessor errors only if the
// specific key it needs is absent.
type keySet struct {
	partnerPubs []*ecdsa.PublicKey // verify GID signatures, the current key first
	partnerPriv *ecdsa.PrivateKey  // signs the /verify-keys response and outbound tokens
	boostxPub   *ecdsa.PublicKey   // verifies inbound Booster/CheckBet/VerifyKeys JWTs
}

// MemoryKeyStore is a multi-tenant key store that holds each partner_id's keys
// in memory. It satisfies the handler and client key-store interfaces and is
// safe for concurrent use: Register may be called while handlers serve requests
// (partner onboarding or key rotation). For keys that live outside the process
// (database, secret manager, KMS), implement handlers.KeyStore (three methods)
// and client.KeyStore (one) directly instead, keyed on partner_id.
type MemoryKeyStore struct {
	mu   sync.RWMutex
	byID map[string]keySet
}

// NewMemoryKeyStore creates an empty MemoryKeyStore. Add partners with Register.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{byID: make(map[string]keySet)}
}

// Register adds or replaces a partner_id's keys: partnerPub verifies GID
// signatures and partnerPriv signs the /verify-keys response and outbound tokens
// (the partner's own key pair), while boostxPub verifies inbound BoostX JWTs.
// Any key may be nil for a partner that only fills some roles (e.g. pass
// nil, priv, nil for an outbound-signing store). All keys land atomically. Safe
// to call concurrently with handler requests. An empty partner is
// ErrMissingClaim; a key that is not a usable P-256 key of its role is
// ErrInvalidPublicKey or ErrInvalidPrivateKey, and keeps the earlier keys.
// To keep earlier partner public keys, use RegisterWithPartnerPublicKeys.
func (s *MemoryKeyStore) Register(partner string, partnerPub *ecdsa.PublicKey, partnerPriv *ecdsa.PrivateKey, boostxPub *ecdsa.PublicKey) error {
	var partnerPubs []*ecdsa.PublicKey
	if partnerPub != nil {
		partnerPubs = []*ecdsa.PublicKey{partnerPub}
	}
	return s.register(partner, partnerPubs, partnerPriv, boostxPub)
}

// RegisterWithPartnerPublicKeys is Register with several partner public keys:
// the current one first, then those of earlier key pairs, kept while games
// started before a rotation still carry GIDs they signed. An empty or nil list
// is ErrInvalidPublicKey; to register no partner public key, call Register
// with a nil one.
func (s *MemoryKeyStore) RegisterWithPartnerPublicKeys(partner string, partnerPubs []*ecdsa.PublicKey, partnerPriv *ecdsa.PrivateKey, boostxPub *ecdsa.PublicKey) error {
	if partner != "" && len(partnerPubs) == 0 {
		return fmt.Errorf("%w: no partner public key for partner %q", tokens.ErrInvalidPublicKey, partner)
	}
	return s.register(partner, partnerPubs, partnerPriv, boostxPub)
}

// register checks every given key against its role and stores the set.
func (s *MemoryKeyStore) register(partner string, partnerPubs []*ecdsa.PublicKey, partnerPriv *ecdsa.PrivateKey, boostxPub *ecdsa.PublicKey) error {
	if partner == "" {
		return fmt.Errorf("%w: partner", tokens.ErrMissingClaim)
	}
	for _, k := range partnerPubs {
		if !usablePublicKey(k) {
			return fmt.Errorf("%w: partner public key for partner %q is not a usable P-256 key", tokens.ErrInvalidPublicKey, partner)
		}
	}
	if partnerPriv != nil && !usablePrivateKey(partnerPriv) {
		return fmt.Errorf("%w: partner private key for partner %q is not a usable P-256 key", tokens.ErrInvalidPrivateKey, partner)
	}
	if boostxPub != nil && !usablePublicKey(boostxPub) {
		return fmt.Errorf("%w: boostx public key for partner %q is not a usable P-256 key", tokens.ErrInvalidPublicKey, partner)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[partner] = keySet{partnerPubs: slices.Clone(partnerPubs), partnerPriv: partnerPriv, boostxPub: boostxPub}
	return nil
}

// usablePublicKey reports whether k is a P-256 key whose point is on the
// curve, the rule the token parsers apply.
func usablePublicKey(k *ecdsa.PublicKey) bool {
	if k == nil || k.Curve != elliptic.P256() || k.X == nil || k.Y == nil {
		return false
	}
	_, err := k.ECDH()
	return err == nil
}

// usablePrivateKey reports whether k is a P-256 key with a valid scalar and a
// public point, the rule the token builders apply.
func usablePrivateKey(k *ecdsa.PrivateKey) bool {
	if k.Curve != elliptic.P256() || k.D == nil || k.X == nil || k.Y == nil {
		return false
	}
	_, err := k.ECDH()
	return err == nil
}

// lookup returns the keys registered for partner, or an error if there are none.
func (s *MemoryKeyStore) lookup(partner string) (keySet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	set, ok := s.byID[partner]
	if !ok {
		return keySet{}, fmt.Errorf("%w %q", ErrUnknownPartner, partner)
	}
	return set, nil
}

// PartnerPublicKey returns the current partner GID-verification public key for partner.
func (s *MemoryKeyStore) PartnerPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error) {
	pubs, err := s.PartnerPublicKeys(ctx, partner)
	if err != nil {
		return nil, err
	}
	return pubs[0], nil
}

// PartnerPublicKeys returns every partner GID-verification public key for
// partner, the current one first.
func (s *MemoryKeyStore) PartnerPublicKeys(_ context.Context, partner string) ([]*ecdsa.PublicKey, error) {
	set, err := s.lookup(partner)
	if err != nil {
		return nil, err
	}
	if len(set.partnerPubs) == 0 {
		return nil, fmt.Errorf("%w: no partner public key for partner %q", tokens.ErrInvalidPublicKey, partner)
	}
	return slices.Clone(set.partnerPubs), nil
}

// PartnerPrivateKey returns the partner's signing key for partner.
func (s *MemoryKeyStore) PartnerPrivateKey(_ context.Context, partner string) (*ecdsa.PrivateKey, error) {
	set, err := s.lookup(partner)
	if err != nil {
		return nil, err
	}
	if set.partnerPriv == nil {
		return nil, fmt.Errorf("%w: no partner private key for partner %q", tokens.ErrInvalidPrivateKey, partner)
	}
	return set.partnerPriv, nil
}

// BoostxPublicKey returns the BoostX inbound-JWT verification key for partner.
func (s *MemoryKeyStore) BoostxPublicKey(_ context.Context, partner string) (*ecdsa.PublicKey, error) {
	set, err := s.lookup(partner)
	if err != nil {
		return nil, err
	}
	if set.boostxPub == nil {
		return nil, fmt.Errorf("%w: no boostx public key for partner %q", tokens.ErrInvalidPublicKey, partner)
	}
	return set.boostxPub, nil
}
