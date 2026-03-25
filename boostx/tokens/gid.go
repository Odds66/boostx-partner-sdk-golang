package tokens

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
)

// GID (Game ID) uniquely identifies a game session.
// It contains three identifying fields plus a cryptographic signature
// proving it was issued by the partner.
type GID struct {
	Partner   string `json:"partner"`   // Partner identifier
	User      string `json:"user"`      // User identifier
	Bet       string `json:"bet"`       // Bet identifier
	Signature string `json:"signature"` // base64url-encoded ES256 signature over canonical {partner, user, bet}
}

// canonicalGIDPayload returns the canonical JSON bytes for GID signing/verification.
func canonicalGIDPayload(partner, user, bet string) ([]byte, error) {
	return json.Marshal(struct {
		Partner string `json:"partner"`
		User    string `json:"user"`
		Bet     string `json:"bet"`
	}{partner, user, bet})
}

// BuildGID creates a signed GID struct.
func BuildGID(partner, user, bet string, privateKey *ecdsa.PrivateKey) (*GID, error) {
	if privateKey == nil {
		return nil, ErrInvalidPrivateKey
	}
	if partner == "" {
		return nil, fmt.Errorf("%w: partner", ErrMissingClaim)
	}
	if user == "" {
		return nil, fmt.Errorf("%w: user", ErrMissingClaim)
	}
	if bet == "" {
		return nil, fmt.Errorf("%w: bet", ErrMissingClaim)
	}

	data, err := canonicalGIDPayload(partner, user, bet)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GID payload: %w", err)
	}

	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign GID: %w", err)
	}

	// Encode signature as R || S (each padded to 32 bytes for P-256)
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	return &GID{
		Partner:   partner,
		User:      user,
		Bet:       bet,
		Signature: base64URLEncode(sig),
	}, nil
}

// VerifyGID verifies the GID signature using the given public key.
func VerifyGID(gid *GID, publicKey *ecdsa.PublicKey) error {
	if publicKey == nil {
		return ErrInvalidPublicKey
	}
	if gid == nil {
		return ErrInvalidGID
	}

	data, err := canonicalGIDPayload(gid.Partner, gid.User, gid.Bet)
	if err != nil {
		return fmt.Errorf("failed to marshal GID payload: %w", err)
	}

	sig, err := base64URLDecode(gid.Signature)
	if err != nil {
		return fmt.Errorf("%w: failed to decode signature", ErrInvalidGID)
	}

	if len(sig) != 64 {
		return fmt.Errorf("%w: invalid signature length", ErrInvalidGID)
	}

	hash := sha256.Sum256(data)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	if !ecdsa.Verify(publicKey, hash[:], r, s) {
		return fmt.Errorf("%w: GID signature verification failed", ErrInvalidSignature)
	}

	return nil
}
