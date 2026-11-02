package tokens

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// jwtHeader is the header SignJWT emits. Parsing reads only alg and crit.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// RegisteredClaims contains the standard JWT claims.
type RegisteredClaims struct {
	IssuedAt int64 `json:"iat,omitempty"`
}

// SignJWT creates a signed JWT token using ES256 (ECDSA P-256 + SHA-256).
func SignJWT(claims any, privateKey *ecdsa.PrivateKey) (string, error) {
	// Encode header
	header := jwtHeader{Alg: "ES256", Typ: "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	headerB64 := base64URLEncode(headerJSON)

	// Encode payload
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	payloadB64 := base64URLEncode(payloadJSON)

	// Create signature input
	signingInput := headerB64 + "." + payloadB64

	signature, err := signES256(privateKey, []byte(signingInput))
	if err != nil {
		return "", err
	}
	signatureB64 := base64URLEncode(signature)

	return signingInput + "." + signatureB64, nil
}

// ParseJWT parses and verifies a JWT token, unmarshaling claims into the provided
// struct. Claim names follow encoding/json, so they match case-insensitively.
func ParseJWT(tokenString string, claims any, publicKey *ecdsa.PublicKey) error {
	if err := checkPublicKey(publicKey); err != nil {
		return err
	}
	payload, err := verifyJWS(tokenString, publicKey)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, claims); err != nil {
		return fmt.Errorf("failed to parse claims: %w", err)
	}
	return nil
}

// ExtractJWTClaims extracts claims from a JWT without verifying the signature.
// WARNING: This should only be used to get identifiers for key lookup.
// Always verify the token afterwards with ParseJWT.
func ExtractJWTClaims(tokenString string, claims any) error {
	payload, err := unverifiedPayload(tokenString)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, claims); err != nil {
		return fmt.Errorf("failed to parse claims: %w", err)
	}
	return nil
}

// verifyJWS checks token's segments and header and its ES256 signature with
// publicKey, which must have passed checkPublicKey, and returns the payload
// JSON. A fault in alg, crit or the signature is ErrInvalidSignature; any other
// is a plain format error.
func verifyJWS(token string, publicKey *ecdsa.PublicKey) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	header, err := decodeJSONSegment(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	members, _ := jsonObject(header)
	if alg, ok := jsonString(members["alg"]); !ok || alg != "ES256" {
		return nil, fmt.Errorf("%w: alg must be ES256", ErrInvalidSignature)
	}
	if _, ok := members["crit"]; ok {
		return nil, fmt.Errorf("%w: crit is not supported", ErrInvalidSignature)
	}

	signature, err := base64URLDecode(parts[2])
	if err != nil || len(signature) != 64 {
		return nil, fmt.Errorf("%w: signature is not 64 bytes of canonical base64url", ErrInvalidSignature)
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !verifyES256(publicKey, hash[:], signature) {
		return nil, ErrInvalidSignature
	}

	payload, err := decodeJSONSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	return payload, nil
}

// unverifiedPayload returns token's payload JSON without verifying the token.
// It never reads the header or the signature.
func unverifiedPayload(token string) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}
	payload, err := decodeJSONSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	return payload, nil
}

// verifiedClaims is verifyJWS returning the payload's members.
func verifiedClaims(token string, publicKey *ecdsa.PublicKey) (map[string]json.RawMessage, error) {
	payload, err := verifyJWS(token, publicKey)
	if err != nil {
		return nil, err
	}
	claims, _ := jsonObject(payload)
	return claims, nil
}

// unverifiedClaims is unverifiedPayload returning the payload's members.
func unverifiedClaims(token string) (map[string]json.RawMessage, error) {
	payload, err := unverifiedPayload(token)
	if err != nil {
		return nil, err
	}
	claims, _ := jsonObject(payload)
	return claims, nil
}

// decodeJSONSegment decodes a header or payload segment, which must be
// canonical base64url of one JSON object in valid UTF-8 with no byte order
// mark and no lone surrogate escape, and returns the JSON from its opening brace.
func decodeJSONSegment(segment string) ([]byte, error) {
	data, err := base64URLDecode(segment)
	if err != nil {
		return nil, errors.New("not canonical base64url")
	}
	if !utf8.Valid(data) {
		return nil, errors.New("not valid UTF-8")
	}
	data = bytes.TrimLeft(data, " \t\r\n")
	if len(data) == 0 || data[0] != '{' || !json.Valid(data) {
		return nil, errors.New("not a single JSON object")
	}
	if hasLoneSurrogate(data) {
		return nil, errors.New("escapes a lone surrogate")
	}
	return data, nil
}

// hasLoneSurrogate reports whether valid JSON text escapes a surrogate (U+D800
// to U+DFFF) that is not a high one followed by an escaped low one;
// encoding/json would read it as U+FFFD.
func hasLoneSurrogate(data []byte) bool {
	hex := func(at int) uint64 {
		v, _ := strconv.ParseUint(string(data[at:at+4]), 16, 16)
		return v
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++ // the escaped character; only a u escape reads further
		if data[i] != 'u' {
			continue
		}
		r := hex(i + 1)
		i += 4
		if r >= 0xDC00 && r <= 0xDFFF {
			return true
		}
		if r >= 0xD800 && r <= 0xDBFF {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return true
			}
			if low := hex(i + 3); low < 0xDC00 || low > 0xDFFF {
				return true
			}
			i += 6
		}
	}
	return false
}

// jsonObject returns the members of a JSON object by exact name, the last of a
// repeated name winning; ok is false for any other JSON value.
func jsonObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, false
	}
	var members map[string]json.RawMessage
	return members, json.Unmarshal(raw, &members) == nil
}

// jsonString reads a JSON string; ok is false for any other JSON value.
func jsonString(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	return s, json.Unmarshal(raw, &s) == nil
}

// jsonBool reads a JSON boolean; ok is false for any other JSON value.
func jsonBool(raw json.RawMessage) (b, ok bool) {
	switch string(raw) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// jsonNumber reads a JSON number as the nearest float64, ±Inf beyond its range;
// ok is false for any other JSON value.
func jsonNumber(raw json.RawMessage) (float64, bool) {
	if len(raw) == 0 || raw[0] != '-' && (raw[0] < '0' || raw[0] > '9') {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	return f, err == nil || errors.Is(err, strconv.ErrRange)
}

// jsonInteger reads a JSON number whose value is an integer of magnitude at
// most 2^53-1, so 3, 3.0 and 3e0 are all 3; ok is false for anything else.
func jsonInteger(raw json.RawMessage) (int64, bool) {
	f, ok := jsonNumber(raw)
	if !ok || f != math.Trunc(f) || math.Abs(f) > float64(maxSafeInteger) {
		return 0, false
	}
	return int64(f), true
}

// readTimeClaims reads the required iat of a Booster or CheckBet payload, and
// refuses an exp that is not after now or an nbf after now, in whole seconds.
func readTimeClaims(claims map[string]json.RawMessage) (int64, error) {
	raw, ok := claims["iat"]
	if !ok {
		return 0, fmt.Errorf("%w: iat", ErrMissingClaim)
	}
	iat, ok := jsonInteger(raw)
	if !ok {
		return 0, fmt.Errorf("%w: iat", ErrInvalidClaim)
	}
	now := float64(time.Now().Unix())
	if raw, ok := claims["exp"]; ok {
		if exp, ok := jsonNumber(raw); !ok || exp <= now {
			return 0, fmt.Errorf("%w: exp", ErrInvalidClaim)
		}
	}
	if raw, ok := claims["nbf"]; ok {
		if nbf, ok := jsonNumber(raw); !ok || nbf > now {
			return 0, fmt.Errorf("%w: nbf", ErrInvalidClaim)
		}
	}
	return iat, nil
}

// signES256 returns the ES256 signature of data as the 64-byte r || s.
func signES256(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	if err := checkPrivateKey(privateKey); err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

// checkPrivateKey returns ErrInvalidPrivateKey unless privateKey is a P-256
// key with a valid scalar and a public point to sign with.
func checkPrivateKey(privateKey *ecdsa.PrivateKey) error {
	if privateKey == nil || privateKey.Curve != elliptic.P256() || privateKey.D == nil || privateKey.X == nil || privateKey.Y == nil {
		return fmt.Errorf("%w: not a P-256 key", ErrInvalidPrivateKey)
	}
	if _, err := privateKey.ECDH(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}
	return nil
}

// checkPublicKey returns ErrInvalidPublicKey unless publicKey is a P-256 key
// whose point is on the curve.
func checkPublicKey(publicKey *ecdsa.PublicKey) error {
	if publicKey == nil || publicKey.Curve != elliptic.P256() || publicKey.X == nil || publicKey.Y == nil {
		return ErrInvalidPublicKey
	}
	if _, err := publicKey.ECDH(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	return nil
}

// checkPublicKeys returns ErrInvalidPublicKey unless some key passes checkPublicKey.
func checkPublicKeys(publicKeys []*ecdsa.PublicKey) error {
	if slices.ContainsFunc(publicKeys, func(k *ecdsa.PublicKey) bool { return checkPublicKey(k) == nil }) {
		return nil
	}
	return ErrInvalidPublicKey
}

// verifyES256 reports whether sig, a 64-byte r || s, signs the SHA-256 digest
// with publicKey, which must have passed checkPublicKey.
func verifyES256(publicKey *ecdsa.PublicKey, digest, sig []byte) bool {
	return ecdsa.Verify(publicKey, digest, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

// base64URLEncode encodes data using base64url encoding without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// base64URLDecode decodes canonical unpadded base64url: only [A-Za-z0-9_-],
// no padding and no stray trailing bits.
func base64URLDecode(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") { // the strict decoder skips them
		return nil, errors.New("illegal base64 data")
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}
