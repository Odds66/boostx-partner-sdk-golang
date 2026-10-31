package tokens

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"regexp"
	"unicode/utf8"
)

// canonicalSignature matches the only GID signature form BoostX accepts: 64 bytes
// as unpadded base64url, whose last character carries no stray bits.
var canonicalSignature = regexp.MustCompile(`^[A-Za-z0-9_-]{85}[AQgw]$`)

// GID (Game ID) uniquely identifies a game session.
// It contains three identifying fields plus a cryptographic signature
// proving it was issued by the partner.
type GID struct {
	Partner   string `json:"partner"`   // Partner identifier
	User      string `json:"user"`      // User identifier
	Bet       string `json:"bet"`       // Bet identifier
	Signature string `json:"signature"` // base64url-encoded ES256 signature over canonical {partner, user, bet}
}

// canonicalGIDPayload returns the canonical JSON bytes a GID signature is computed over.
// They are a wire contract: BoostX verifies the signature over its own encoding,
// JavaScript's JSON.stringify({partner, user, bet}), which encoding/json cannot produce
// at any setting: json.Marshal escapes <, > and & as
// \u003c, \u003e and \u0026, which JSON.stringify does not; SetEscapeHTML(false) fixes those
// three but still escapes U+2028 and U+2029 unconditionally, which JSON.stringify also leaves
// literal. An identifier with any of the five would be signed over bytes BoostX never
// reproduces and rejected as if the key were wrong — invisibly to round-trip tests,
// since VerifyGID shares the encoder. Field order is fixed and must not change.
func canonicalGIDPayload(partner, user, bet string) []byte {
	var b bytes.Buffer
	// Small over-estimate for the keys, quotes and separators; beats regrowing.
	b.Grow(len(partner) + len(user) + len(bet) + 40)
	b.WriteString(`{"partner":`)
	writeJSONStringifyString(&b, partner)
	b.WriteString(`,"user":`)
	writeJSONStringifyString(&b, user)
	b.WriteString(`,"bet":`)
	writeJSONStringifyString(&b, bet)
	b.WriteByte('}')
	return b.Bytes()
}

// writeJSONStringifyString writes s as a JSON string literal using exactly the escapes
// JavaScript's JSON.stringify applies: the two mandatory ones, the five short forms for
// control characters that have them, and \u00XX for the remaining C0 range. Everything
// else — including <, >, &, U+2028 and U+2029 — is written through verbatim.
func writeJSONStringifyString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\b':
			b.WriteString(`\b`)
		case c == '\f':
			b.WriteString(`\f`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20:
			fmt.Fprintf(b, `\u%04x`, c)
		default:
			// For valid UTF-8 this reproduces the source bytes — what TextEncoder produces.
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
}

// BuildGID creates a signed GID struct. Identifiers must be valid UTF-8.
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
	// Invalid UTF-8 travels as U+FFFD (encoding/json) while the signature covers the
	// raw bytes — such a token can never verify. Fail fast here instead.
	if !utf8.ValidString(partner) {
		return nil, fmt.Errorf("%w: partner is not valid UTF-8", ErrInvalidClaim)
	}
	if !utf8.ValidString(user) {
		return nil, fmt.Errorf("%w: user is not valid UTF-8", ErrInvalidClaim)
	}
	if !utf8.ValidString(bet) {
		return nil, fmt.Errorf("%w: bet is not valid UTF-8", ErrInvalidClaim)
	}

	sig, err := signES256(privateKey, canonicalGIDPayload(partner, user, bet))
	if err != nil {
		return nil, err
	}

	return &GID{
		Partner:   partner,
		User:      user,
		Bet:       bet,
		Signature: base64URLEncode(sig),
	}, nil
}

// VerifyGID verifies the GID signature using the given public key. Like BoostX,
// it accepts only the canonical form: 86 characters of unpadded base64url.
func VerifyGID(gid *GID, publicKey *ecdsa.PublicKey) error {
	if err := checkPublicKey(publicKey); err != nil {
		return err
	}
	return verifyGIDWithKeys(gid, []*ecdsa.PublicKey{publicKey})
}

// verifyGIDWithKeys accepts the GID when its signature is in the canonical form
// and any of publicKeys verifies it. Unusable keys are skipped; ErrInvalidPublicKey
// when none is usable.
func verifyGIDWithKeys(gid *GID, publicKeys []*ecdsa.PublicKey) error {
	if err := checkPublicKeys(publicKeys); err != nil {
		return err
	}
	if gid == nil {
		return ErrInvalidGID
	}
	if !canonicalSignature.MatchString(gid.Signature) {
		return fmt.Errorf("%w: %w: signature is not canonical base64url", ErrInvalidGID, ErrInvalidSignature)
	}

	sig, err := base64URLDecode(gid.Signature)
	if err != nil {
		return fmt.Errorf("%w: failed to decode signature", ErrInvalidGID)
	}

	if len(sig) != 64 {
		return fmt.Errorf("%w: invalid signature length", ErrInvalidGID)
	}

	hash := sha256.Sum256(canonicalGIDPayload(gid.Partner, gid.User, gid.Bet))
	for _, k := range publicKeys {
		if checkPublicKey(k) == nil && verifyES256(k, hash[:], sig) {
			return nil
		}
	}

	return fmt.Errorf("%w: %w: GID signature verification failed", ErrInvalidGID, ErrInvalidSignature)
}
