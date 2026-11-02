// Package keys provides utilities for loading ECDSA P-256 keys.
package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// LoadPrivateKeyFromPEM parses an ECDSA P-256 private key from PEM-encoded data:
// the first PRIVATE KEY block, read as PKCS#8, or EC PRIVATE KEY block, read as
// SEC1. A literal \n reads as a line break. The DER must be that structure and
// nothing else: a version 0 PrivateKeyInfo for P-256 with no optional field but
// attributes, holding a version 1 ECPrivateKey whose parameters, if present,
// name P-256. A public key embedded in the key must be the uncompressed point
// of its scalar.
func LoadPrivateKeyFromPEM(pemData []byte) (*ecdsa.PrivateKey, error) {
	label, der, err := pemBlock(pemData, "PRIVATE KEY", "EC PRIVATE KEY")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", tokens.ErrInvalidPrivateKey, err)
	}

	var privateKey *ecdsa.PrivateKey
	sec1 := der
	if label == "EC PRIVATE KEY" {
		if privateKey, err = x509.ParseECPrivateKey(der); err != nil {
			return nil, fmt.Errorf("%w: %v", tokens.ErrInvalidPrivateKey, err)
		}
	} else {
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", tokens.ErrInvalidPrivateKey, err)
		}
		var ok bool
		if privateKey, ok = key.(*ecdsa.PrivateKey); !ok {
			return nil, fmt.Errorf("%w: key is not ECDSA", tokens.ErrInvalidPrivateKey)
		}
		if sec1, ok = p256PrivateKeyInfo(der); !ok {
			return nil, fmt.Errorf("%w: not a version 0 PrivateKeyInfo for P-256", tokens.ErrInvalidPrivateKey)
		}
	}

	// Validate P-256 curve
	if privateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: key must use P-256 curve", tokens.ErrInvalidPrivateKey)
	}
	if err := checkECPrivateKey(sec1, privateKey); err != nil {
		return nil, fmt.Errorf("%w: %v", tokens.ErrInvalidPrivateKey, err)
	}

	return privateKey, nil
}

// pkcs8 is a PKCS#8 PrivateKeyInfo with its algorithm and optional fields
// kept as written; Rest catches any element after them.
type pkcs8 struct {
	Version    int
	Algo       asn1.RawValue
	PrivateKey []byte
	Attributes asn1.RawValue `asn1:"optional"`
	Rest       asn1.RawValue `asn1:"optional"`
}

// p256Algorithm is the AlgorithmIdentifier { id-ecPublicKey, prime256v1 }.
var p256Algorithm = []byte{0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

// p256PrivateKeyInfo returns the privateKey of der if der is exactly a
// version 0 PrivateKeyInfo with the P-256 AlgorithmIdentifier and nothing
// after privateKey but optional [0] attributes, which are not read. x509 takes
// any version, ignores what follows privateKey and octets after the structure.
func p256PrivateKeyInfo(der []byte) ([]byte, bool) {
	var info pkcs8
	rest, err := asn1.Unmarshal(der, &info)
	attributes := info.Attributes.FullBytes == nil ||
		info.Attributes.Class == asn1.ClassContextSpecific && info.Attributes.Tag == 0 && info.Attributes.IsCompound
	ok := err == nil && len(rest) == 0 && info.Version == 0 && bytes.Equal(info.Algo.FullBytes, p256Algorithm) &&
		attributes && info.Rest.FullBytes == nil
	return info.PrivateKey, ok
}

// ecPrivateKey is a SEC1 ECPrivateKey with its optional fields kept as
// written; Rest catches any element after them.
type ecPrivateKey struct {
	Version    int
	PrivateKey []byte
	Parameters asn1.RawValue `asn1:"optional,explicit,tag:0"`
	PublicKey  asn1.RawValue `asn1:"optional,explicit,tag:1"`
	Rest       asn1.RawValue `asn1:"optional"`
}

// p256Parameters is [0] { namedCurve prime256v1 }.
var p256Parameters = []byte{0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

// checkECPrivateKey checks what x509 does not: that the ECPrivateKey sec1 has
// nothing after it, names P-256 if it has parameters, holds no other element,
// and has no [1] public key or one that is exactly a BIT STRING holding the
// uncompressed point of key. x509 reads the curve of a PKCS#8 key from its
// AlgorithmIdentifier and ignores [1], and encoding/asn1 reads a mistyped
// optional field as absent, so the fields are compared as written.
func checkECPrivateKey(sec1 []byte, key *ecdsa.PrivateKey) error {
	var k ecPrivateKey
	if rest, err := asn1.Unmarshal(sec1, &k); err != nil || len(rest) != 0 || k.Rest.FullBytes != nil ||
		k.Parameters.FullBytes != nil && !bytes.Equal(k.Parameters.FullBytes, p256Parameters) {
		return errors.New("malformed ECPrivateKey")
	}
	if k.PublicKey.FullBytes == nil {
		return nil
	}
	point, err := key.PublicKey.ECDH()
	if err != nil || !bytes.Equal(k.PublicKey.FullBytes, append([]byte{0xa1, 0x44, 0x03, 0x42, 0x00}, point.Bytes()...)) {
		return errors.New("the embedded public key is not the uncompressed point of the private key")
	}
	return nil
}

// LoadPrivateKeyFromFile reads and parses an ECDSA P-256 private key from a
// file. A read failure wraps both ErrInvalidPrivateKey and the OS error.
func LoadPrivateKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", tokens.ErrInvalidPrivateKey, err)
	}
	return LoadPrivateKeyFromPEM(data)
}

// LoadPublicKeyFromPEM parses an ECDSA P-256 public key from PEM-encoded data:
// the first PUBLIC KEY block. A literal \n reads as a line break. A key whose
// BIT STRING declares unused bits is refused.
func LoadPublicKeyFromPEM(pemData []byte) (*ecdsa.PublicKey, error) {
	_, der, err := pemBlock(pemData, "PUBLIC KEY")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", tokens.ErrInvalidPublicKey, err)
	}

	// x509 shifts the BIT STRING by its declared unused bits, so a point stored
	// shifted left loads as that point; spec KEYS-12 refuses any unused bits.
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err == nil && spki.PublicKey.BitLength%8 != 0 {
		return nil, fmt.Errorf("%w: the key's BIT STRING declares unused bits", tokens.ErrInvalidPublicKey)
	}

	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", tokens.ErrInvalidPublicKey, err)
	}
	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: key is not ECDSA", tokens.ErrInvalidPublicKey)
	}

	// Validate P-256 curve
	if publicKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: key must use P-256 curve", tokens.ErrInvalidPublicKey)
	}

	return publicKey, nil
}

// LoadPublicKeyFromFile reads and parses an ECDSA P-256 public key from a
// file. A read failure wraps both ErrInvalidPublicKey and the OS error.
func LoadPublicKeyFromFile(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", tokens.ErrInvalidPublicKey, err)
	}
	return LoadPublicKeyFromPEM(data)
}

// pemBlock finds the earliest "-----BEGIN L-----" whose label L is one of
// labels, case-sensitively, and returns L and its body, up to the first
// "-----END L-----" after it, decoded as padded standard base64 once PEM
// whitespace is removed. Text around the block is ignored, and a literal \r\n
// or \n reads as a line break, as keys kept in environment variables often
// arrive. Header lines such as "Proc-Type:" are not supported.
func pemBlock(data []byte, labels ...string) (string, []byte, error) {
	text := strings.NewReplacer(`\r\n`, "\n", `\n`, "\n").Replace(string(data))
	label, start := "", -1
	for _, l := range labels {
		if i := strings.Index(text, "-----BEGIN "+l+"-----"); i >= 0 && (start < 0 || i < start) {
			label, start = l, i
		}
	}
	if start < 0 {
		if strings.Contains(text, "-----BEGIN ENCRYPTED PRIVATE KEY-----") {
			return "", nil, errors.New("an ENCRYPTED PRIVATE KEY is not supported, decrypt it first")
		}
		return "", nil, fmt.Errorf("no %s PEM block", strings.Join(labels, " or "))
	}

	body := text[start+len("-----BEGIN "+label+"-----"):]
	end := strings.Index(body, "-----END "+label+"-----")
	if end < 0 {
		return "", nil, fmt.Errorf("the %s PEM block has no END line", label)
	}
	body = body[:end]
	if strings.Contains(body, "Proc-Type: 4,ENCRYPTED") {
		return "", nil, fmt.Errorf("an encrypted %s is not supported, decrypt it first", label)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Map(func(r rune) rune {
		if strings.ContainsRune(" \t\n\v\f\r", r) {
			return -1
		}
		return r
	}, body))
	if err != nil {
		return "", nil, fmt.Errorf("the %s PEM body is not base64", label)
	}
	return label, der, nil
}
