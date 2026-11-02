package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

func generateTestPEMKeys(t *testing.T) (privateKeyPEM, publicKeyPEM []byte, privateKey *ecdsa.PrivateKey) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode private key
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	privateKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	// Encode public key
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	publicKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return privateKeyPEM, publicKeyPEM, privateKey
}

func TestLoadPrivateKeyFromPEM(t *testing.T) {
	privateKeyPEM, _, originalKey := generateTestPEMKeys(t)

	loaded, err := LoadPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromPEM failed: %v", err)
	}

	// Verify it's the same key by comparing public key coordinates
	if loaded.PublicKey.X.Cmp(originalKey.PublicKey.X) != 0 ||
		loaded.PublicKey.Y.Cmp(originalKey.PublicKey.Y) != 0 {
		t.Error("loaded key does not match original")
	}
}

func TestLoadPrivateKeyFromPEM_ECPrivateKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Use EC PRIVATE KEY format
	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal EC private key: %v", err)
	}
	ecPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	loaded, err := LoadPrivateKeyFromPEM(ecPrivateKeyPEM)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromPEM (EC format) failed: %v", err)
	}

	if loaded.PublicKey.X.Cmp(privateKey.PublicKey.X) != 0 {
		t.Error("loaded key does not match original")
	}
}

func TestLoadPrivateKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := LoadPrivateKeyFromPEM([]byte("not a pem"))
	if !errors.Is(err, tokens.ErrInvalidPrivateKey) {
		t.Errorf("expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestLoadPublicKeyFromPEM(t *testing.T) {
	_, publicKeyPEM, originalKey := generateTestPEMKeys(t)

	loaded, err := LoadPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		t.Fatalf("LoadPublicKeyFromPEM failed: %v", err)
	}

	if loaded.X.Cmp(originalKey.PublicKey.X) != 0 ||
		loaded.Y.Cmp(originalKey.PublicKey.Y) != 0 {
		t.Error("loaded key does not match original")
	}
}

func TestLoadPublicKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := LoadPublicKeyFromPEM([]byte("not a pem"))
	if !errors.Is(err, tokens.ErrInvalidPublicKey) {
		t.Errorf("expected ErrInvalidPublicKey, got %v", err)
	}
}

// TestLoadPublicKeyFromPEM_UnusedBits pins that an SPKI whose BIT STRING
// declares an unused bit is refused, here with the point stored shifted left
// one bit, which x509 alone reads back as the original key.
func TestLoadPublicKeyFromPEM_UnusedBits(t *testing.T) {
	_, pubPEM, key := generateTestPEMKeys(t)
	block, _ := pem.Decode(pubPEM)
	der := slices.Clone(block.Bytes) // 26 fixed octets, the last the unused-bit count, then 0x04 || X || Y
	der[25] = 1
	point := new(big.Int).SetBytes(block.Bytes[26:])
	point.Lsh(point, 1).FillBytes(der[26:])
	if k, err := x509.ParsePKIXPublicKey(der); err != nil || !key.PublicKey.Equal(k) {
		t.Fatalf("test input: x509 should read the shifted point as the key, got %v", err)
	}

	_, err := LoadPublicKeyFromPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if !errors.Is(err, tokens.ErrInvalidPublicKey) {
		t.Errorf("expected ErrInvalidPublicKey, got %v", err)
	}
}

func TestLoadPrivateKeyFromFile(t *testing.T) {
	privateKeyPEM, _, _ := generateTestPEMKeys(t)

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "private.pem")

	if err := os.WriteFile(keyPath, privateKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	loaded, err := LoadPrivateKeyFromFile(keyPath)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromFile failed: %v", err)
	}

	if loaded == nil {
		t.Error("expected non-nil key")
	}
}

func TestLoadPrivateKeyFromFile_NotFound(t *testing.T) {
	_, err := LoadPrivateKeyFromFile("/nonexistent/path/key.pem")
	if !errors.Is(err, tokens.ErrInvalidPrivateKey) || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected ErrInvalidPrivateKey and fs.ErrNotExist, got %v", err)
	}
}

func TestLoadPublicKeyFromFile(t *testing.T) {
	_, publicKeyPEM, _ := generateTestPEMKeys(t)

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "public.pem")

	if err := os.WriteFile(keyPath, publicKeyPEM, 0644); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	loaded, err := LoadPublicKeyFromFile(keyPath)
	if err != nil {
		t.Fatalf("LoadPublicKeyFromFile failed: %v", err)
	}

	if loaded == nil {
		t.Error("expected non-nil key")
	}
}

func TestLoadPublicKeyFromFile_NotFound(t *testing.T) {
	_, err := LoadPublicKeyFromFile("/nonexistent/path/key.pem")
	if !errors.Is(err, tokens.ErrInvalidPublicKey) || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected ErrInvalidPublicKey and fs.ErrNotExist, got %v", err)
	}
}

// TestLoadKeyFromPEM_Forms pins the forms keys arrive in from environment
// variables, secret managers and tools: escaped line breaks, a BOM, text around
// the block, indentation, one line, and more than one PEM block, the wanted
// label found wherever it is.
func TestLoadKeyFromPEM_Forms(t *testing.T) {
	privPEM, pubPEM, key := generateTestPEMKeys(t)
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal EC private key: %v", err)
	}
	sec1PEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})
	otherPKCS8, _, other := generateTestPEMKeys(t)
	otherSEC1, err := x509.MarshalECPrivateKey(other)
	if err != nil {
		t.Fatalf("failed to marshal EC private key: %v", err)
	}
	otherSEC1PEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: otherSEC1})
	// The P-256 OID, as openssl ecparam -genkey writes ahead of the key.
	paramsPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}})
	escaped := func(data []byte, lineBreak string) []byte {
		return bytes.ReplaceAll(data, []byte("\n"), []byte(lineBreak))
	}
	bom := []byte("\xef\xbb\xbf")
	indented := func(data []byte) []byte {
		return slices.Concat([]byte("    "), bytes.ReplaceAll(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"), []byte("\n    ")))
	}
	oneLine := func(data []byte) []byte { return bytes.ReplaceAll(data, []byte("\n"), nil) }

	for name, data := range map[string][]byte{
		"PKCS#8, escaped LF":   escaped(privPEM, `\n`),
		"PKCS#8, escaped CRLF": escaped(privPEM, `\r\n`),
		"SEC1, escaped LF":     escaped(sec1PEM, `\n`),
		"SEC1, escaped CRLF":   escaped(sec1PEM, `\r\n`),
		"BOM":                  slices.Concat(bom, privPEM),
		"EC PARAMETERS first":  slices.Concat(paramsPEM, sec1PEM),
		"bundle":               slices.Concat(privPEM, pubPEM),
		"wanted block second":  slices.Concat(pubPEM, privPEM),
		"SEC1, then PKCS#8":    slices.Concat(sec1PEM, otherPKCS8), // the earliest wanted label wins
		"PKCS#8, then SEC1":    slices.Concat(privPEM, otherSEC1PEM),
		"prefix on the line":   slices.Concat([]byte("PARTNER_KEY="), privPEM),
		"text after END":       slices.Concat(privPEM, []byte("-----END PUBLIC KEY-----trailing")),
		"indented":             indented(privPEM),
		"SEC1 indented":        indented(sec1PEM),
		"one line":             oneLine(privPEM),
	} {
		got, err := LoadPrivateKeyFromPEM(data)
		if err != nil || !got.Equal(key) {
			t.Errorf("private key, %s: not the original key (err %v)", name, err)
		}
	}

	for name, data := range map[string][]byte{
		"escaped LF":   escaped(pubPEM, `\n`),
		"escaped CRLF": escaped(pubPEM, `\r\n`),
		"BOM":          slices.Concat(bom, pubPEM),
		"bundle":       slices.Concat(privPEM, pubPEM),
		"one line":     oneLine(pubPEM),
		"indented":     indented(pubPEM),
	} {
		got, err := LoadPublicKeyFromPEM(data)
		if err != nil || !got.Equal(&key.PublicKey) {
			t.Errorf("public key, %s: not the original key (err %v)", name, err)
		}
	}
}

// TestLoadKeyFromPEM_Refused pins that the label decides both which block is
// read and how its body is parsed, and that a block the spec does not support
// is refused with the role's key error.
func TestLoadKeyFromPEM_Refused(t *testing.T) {
	privPEM, pubPEM, key := generateTestPEMKeys(t)
	sec1, _ := x509.MarshalECPrivateKey(key)
	pkcs8, _ := pem.Decode(privPEM)
	spki, _ := pem.Decode(pubPEM)
	block := func(label string, der []byte) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der})
	}
	relabel := func(data []byte, from, to string) []byte {
		return bytes.ReplaceAll(data, []byte(from), []byte(to))
	}
	withHeader := func(data []byte, header string) []byte {
		return bytes.Replace(data, []byte("-----\n"), []byte("-----\n"+header+"\n\n"), 1)
	}

	for name, data := range map[string][]byte{
		"ECDSA PRIVATE KEY label":     block("ECDSA PRIVATE KEY", pkcs8.Bytes),
		"lower-case label":            block("private key", pkcs8.Bytes),
		"public key only":             pubPEM,
		"PKCS#8 under EC PRIVATE KEY": block("EC PRIVATE KEY", pkcs8.Bytes),
		"SEC1 under PRIVATE KEY":      block("PRIVATE KEY", sec1),
		"no END line":                 bytes.TrimSuffix(privPEM, []byte("-----END PRIVATE KEY-----\n")),
		"mismatched END":              relabel(privPEM, "END PRIVATE KEY", "END EC PRIVATE KEY"),
		"header line":                 withHeader(privPEM, "Comment: partner key"),
		"encrypted header":            withHeader(block("EC PRIVATE KEY", sec1), "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00"),
		"ENCRYPTED PRIVATE KEY":       block("ENCRYPTED PRIVATE KEY", pkcs8.Bytes),
		"unpadded body":               []byte("-----BEGIN PRIVATE KEY-----\nAAAAA\n-----END PRIVATE KEY-----\n"),
		"empty":                       nil,
	} {
		if _, err := LoadPrivateKeyFromPEM(data); !errors.Is(err, tokens.ErrInvalidPrivateKey) {
			t.Errorf("private key, %s: expected ErrInvalidPrivateKey, got %v", name, err)
		}
	}
	for _, data := range [][]byte{block("ENCRYPTED PRIVATE KEY", pkcs8.Bytes), withHeader(block("EC PRIVATE KEY", sec1), "Proc-Type: 4,ENCRYPTED")} {
		if _, err := LoadPrivateKeyFromPEM(data); err == nil || !strings.Contains(err.Error(), "decrypt it first") {
			t.Errorf("encrypted key: expected a message to decrypt it first, got %v", err)
		}
	}

	for name, data := range map[string][]byte{
		"CERTIFICATE label": block("CERTIFICATE", spki.Bytes),
		"lower-case label":  block("public key", spki.Bytes),
		"private key only":  privPEM,
		"header line":       withHeader(pubPEM, "Comment: boostx"),
		"mismatched END":    relabel(pubPEM, "END PUBLIC KEY", "END PRIVATE KEY"),
	} {
		if _, err := LoadPublicKeyFromPEM(data); !errors.Is(err, tokens.ErrInvalidPublicKey) {
			t.Errorf("public key, %s: expected ErrInvalidPublicKey, got %v", name, err)
		}
	}
}

// tlv encodes one DER element whose content is the concatenation of content.
func tlv(tag byte, content ...[]byte) []byte {
	c := bytes.Join(content, nil)
	switch n := len(c); {
	case n < 0x80:
		return append([]byte{tag, byte(n)}, c...)
	case n < 0x100:
		return append([]byte{tag, 0x81, byte(n)}, c...)
	default:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, c...)
	}
}

// ecKey is a version 1 ECPrivateKey holding the scalar of key and then fields.
func ecKey(key *ecdsa.PrivateKey, fields ...[]byte) []byte {
	return tlv(0x30, []byte{0x02, 0x01, 0x01}, tlv(0x04, key.D.FillBytes(make([]byte, 32))), bytes.Join(fields, nil))
}

// privateKeyInfo is a version 0 P-256 PrivateKeyInfo holding sec1 and then after.
func privateKeyInfo(sec1 []byte, after ...[]byte) []byte {
	return tlv(0x30, []byte{0x02, 0x01, 0x00}, p256Algorithm, tlv(0x04, sec1), bytes.Join(after, nil))
}

// embeddedPublicKey is a [1] public key field holding point.
func embeddedPublicKey(point []byte) []byte {
	return tlv(0xa1, tlv(0x03, []byte{0}, point))
}

func loadDER(label string, der []byte) error {
	_, err := LoadPrivateKeyFromPEM(pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der}))
	return err
}

// TestLoadPrivateKeyFromPEM_EmbeddedPublicKey pins that the optional [1]
// public key of an ECPrivateKey, standalone or inside PKCS#8, loads only when
// it is a BIT STRING holding the uncompressed point of the scalar, and that a
// key without it loads.
func TestLoadPrivateKeyFromPEM_EmbeddedPublicKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	own, _ := key.PublicKey.ECDH()
	foreign, _ := other.PublicKey.ECDH()
	compressed := elliptic.MarshalCompressed(elliptic.P256(), key.X, key.Y)
	hybrid := append([]byte{6 | compressed[0]&1}, own.Bytes()[1:]...)
	offCurve := bytes.Clone(own.Bytes())
	offCurve[64] ^= 1
	load := func(field []byte) map[string]error {
		return map[string]error{
			"SEC1":   loadDER("EC PRIVATE KEY", ecKey(key, p256Parameters, field)),
			"PKCS#8": loadDER("PRIVATE KEY", privateKeyInfo(ecKey(key, field))),
		}
	}

	for name, field := range map[string][]byte{"own point": embeddedPublicKey(own.Bytes()), "no public key": nil} {
		for form, err := range load(field) {
			if err != nil {
				t.Errorf("%s, %s: expected the key to load, got %v", form, name, err)
			}
		}
	}
	for name, field := range map[string][]byte{
		"another key's point":    embeddedPublicKey(foreign.Bytes()),
		"compressed":             embeddedPublicKey(compressed),
		"hybrid":                 embeddedPublicKey(hybrid),
		"off the curve":          embeddedPublicKey(offCurve),
		"point at infinity":      embeddedPublicKey([]byte{0}),
		"no 0x04 prefix":         embeddedPublicKey(own.Bytes()[1:]),
		"66 octets":              embeddedPublicKey(append(own.Bytes(), 0)),
		"empty BIT STRING":       tlv(0xa1, tlv(0x03)),
		"unused bits":            tlv(0xa1, tlv(0x03, []byte{1}, own.Bytes())),
		"OCTET STRING":           tlv(0xa1, tlv(0x04, foreign.Bytes())),
		"constructed BIT STRING": tlv(0xa1, tlv(0x23, tlv(0x03, []byte{0}, foreign.Bytes()))),
		"implicit [1]":           tlv(0x81, []byte{0}, foreign.Bytes()),
	} {
		for form, err := range load(field) {
			if !errors.Is(err, tokens.ErrInvalidPrivateKey) {
				t.Errorf("%s, %s: expected ErrInvalidPrivateKey, got %v", form, name, err)
			}
		}
	}
}

// TestLoadPrivateKeyFromPEM_Structure pins that the DER is exactly the
// structure its label names, which x509 alone does not check.
func TestLoadPrivateKeyFromPEM_Structure(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	own, _ := key.PublicKey.ECDH()
	foreign, _ := other.PublicKey.ECDH()
	ownPub := embeddedPublicKey(own.Bytes())
	sec1 := ecKey(key, p256Parameters, ownPub)
	inner := ecKey(key, ownPub)
	scalar := tlv(0x04, key.D.FillBytes(make([]byte, 32)))
	idECPublicKey := tlv(0x06, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01})
	info := func(version byte, algorithm, sec1 []byte, after ...[]byte) []byte {
		return tlv(0x30, []byte{0x02, 0x01, version}, algorithm, tlv(0x04, sec1), bytes.Join(after, nil))
	}
	type der struct {
		label string
		der   []byte
	}

	for name, c := range map[string]der{
		"SEC1":                        {"EC PRIVATE KEY", sec1},
		"PKCS#8 with attributes":      {"PRIVATE KEY", privateKeyInfo(inner, tlv(0xa0))},
		"PKCS#8 with inner P-256 [0]": {"PRIVATE KEY", privateKeyInfo(sec1)},
	} {
		if err := loadDER(c.label, c.der); err != nil {
			t.Errorf("%s: expected the key to load, got %v", name, err)
		}
	}
	for name, c := range map[string]der{
		"SEC1, octets after it":                {"EC PRIVATE KEY", append(bytes.Clone(sec1), 0, 0)},
		"SEC1, non-minimal length":             {"EC PRIVATE KEY", append([]byte{0x30, 0x81}, sec1[1:]...)},
		"SEC1, inner version 2":                {"EC PRIVATE KEY", tlv(0x30, []byte{0x02, 0x01, 0x02}, scalar, p256Parameters, ownPub)},
		"SEC1, [0] twice":                      {"EC PRIVATE KEY", ecKey(key, p256Parameters, p256Parameters, ownPub)},
		"SEC1, [1] twice":                      {"EC PRIVATE KEY", ecKey(key, p256Parameters, ownPub, embeddedPublicKey(foreign.Bytes()))},
		"SEC1, [0] after [1]":                  {"EC PRIVATE KEY", ecKey(key, ownPub, p256Parameters)},
		"SEC1, [2] after [1]":                  {"EC PRIVATE KEY", ecKey(key, p256Parameters, ownPub, tlv(0xa2, []byte{0x05, 0x00}))},
		"PKCS#8, octets after it":              {"PRIVATE KEY", append(privateKeyInfo(inner), 0, 0)},
		"PKCS#8, octets after the inner key":   {"PRIVATE KEY", privateKeyInfo(append(bytes.Clone(inner), 0, 0))},
		"PKCS#8 version 1":                     {"PRIVATE KEY", info(1, p256Algorithm, inner)},
		"PKCS#8 version 1 with its public key": {"PRIVATE KEY", info(1, p256Algorithm, inner, tlv(0x81, []byte{0}, own.Bytes()))},
		"PKCS#8 version 2":                     {"PRIVATE KEY", info(2, p256Algorithm, inner)},
		"PKCS#8, public key after privateKey":  {"PRIVATE KEY", privateKeyInfo(inner, tlv(0x81, []byte{0}, own.Bytes()))},
		"PKCS#8, element after attributes":     {"PRIVATE KEY", privateKeyInfo(inner, tlv(0xa0), tlv(0xa1))},
		"PKCS#8, stray octet after privateKey": {"PRIVATE KEY", privateKeyInfo(inner, []byte{0x05})},
		"PKCS#8, algorithm without curve":      {"PRIVATE KEY", info(0, tlv(0x30, idECPublicKey), sec1)},
		"PKCS#8, algorithm with NULL":          {"PRIVATE KEY", info(0, tlv(0x30, idECPublicKey, []byte{0x05, 0x00}), sec1)},
		"PKCS#8, inner version 2":              {"PRIVATE KEY", privateKeyInfo(tlv(0x30, []byte{0x02, 0x01, 0x02}, scalar, ownPub))},
		"PKCS#8, inner [0] naming P-384":       {"PRIVATE KEY", privateKeyInfo(ecKey(key, tlv(0xa0, tlv(0x06, []byte{0x2b, 0x81, 0x04, 0x00, 0x22})), ownPub))},
		"PKCS#8, inner explicit parameters":    {"PRIVATE KEY", privateKeyInfo(ecKey(key, tlv(0xa0, tlv(0x30, []byte{0x02, 0x01, 0x01})), ownPub))},
	} {
		if err := loadDER(c.label, c.der); !errors.Is(err, tokens.ErrInvalidPrivateKey) {
			t.Errorf("%s: expected ErrInvalidPrivateKey, got %v", name, err)
		}
	}
}
