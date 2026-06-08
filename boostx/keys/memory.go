package keys

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"sync"
)

// ErrUnknownPartner is returned (wrapped) by a MemoryKeyStore lookup when no
// keys are registered for the partner_id. The mounted handlers map it to a 400.
var ErrUnknownPartner = errors.New("unknown partner")

// keySet is a partner's stored keys. Any field may be nil when the partner only
// fills some roles (sign-only or verify-only); each accessor errors only if the
// specific key it needs is absent.
type keySet struct {
	partnerPub  *ecdsa.PublicKey  // verifies GID signatures
	partnerPriv *ecdsa.PrivateKey // signs the /verify-keys response and outbound tokens
	boostxPub   *ecdsa.PublicKey  // verifies inbound Booster/CheckBet/VerifyKeys JWTs
}

// MemoryKeyStore is a multi-tenant key store that holds each partner_id's keys
// in memory. It satisfies the handler and client key-store interfaces and is
// safe for concurrent use: Register may be called while handlers serve requests
// (partner onboarding or key rotation). For keys that live outside the process
// (database, secret manager, KMS), implement handlers.KeyStore / client.KeyStore
// directly instead — both are three small methods keyed on partner_id.
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
// to call concurrently with handler requests; errors if partner is empty.
func (s *MemoryKeyStore) Register(partner string, partnerPub *ecdsa.PublicKey, partnerPriv *ecdsa.PrivateKey, boostxPub *ecdsa.PublicKey) error {
	if partner == "" {
		return errors.New("partner must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[partner] = keySet{partnerPub: partnerPub, partnerPriv: partnerPriv, boostxPub: boostxPub}
	return nil
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

// PartnerPublicKey returns the partner's GID-verification public key for partner.
func (s *MemoryKeyStore) PartnerPublicKey(_ context.Context, partner string) (*ecdsa.PublicKey, error) {
	set, err := s.lookup(partner)
	if err != nil {
		return nil, err
	}
	if set.partnerPub == nil {
		return nil, fmt.Errorf("no partner public key for partner %q", partner)
	}
	return set.partnerPub, nil
}

// PartnerPrivateKey returns the partner's signing key for partner.
func (s *MemoryKeyStore) PartnerPrivateKey(_ context.Context, partner string) (*ecdsa.PrivateKey, error) {
	set, err := s.lookup(partner)
	if err != nil {
		return nil, err
	}
	if set.partnerPriv == nil {
		return nil, fmt.Errorf("no partner private key for partner %q", partner)
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
		return nil, fmt.Errorf("no boostx public key for partner %q", partner)
	}
	return set.boostxPub, nil
}
