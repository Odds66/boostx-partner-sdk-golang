package tokens

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestGIDRoundTripSurvivesHTMLSensitiveCharacters checks ids with the characters
// encoding/json escapes and JSON.stringify does not verify end to end. Build and verify share the encoder, so only the
// spec's vectors (gidgp.json and golden/gid-signature.json), not this test, can catch an encoding regression.
func TestGIDRoundTripSurvivesHTMLSensitiveCharacters(t *testing.T) {
	priv, pub := generateTestKey(t)

	for _, id := range []string{"acme&co", "u<1>", "a\u2028b"} {
		t.Run(id, func(t *testing.T) {
			gid, err := BuildGID("partner", id, "bet-"+id, priv)
			if err != nil {
				t.Fatalf("BuildGID: %v", err)
			}
			if err := VerifyGID(gid, pub); err != nil {
				t.Errorf("VerifyGID: %v", err)
			}
		})
	}
}

// gidSignatureVector is the spec's GID signature vector, testdata/spec/golden/gid-signature.json.
// Its key pair is a published test pair, never a real partner key.
type gidSignatureVector struct {
	PrivateKeyPkcs8 string `json:"privateKeyPkcs8"`
	PublicKeySpki   string `json:"publicKeySpki"`
	GID             GID    `json:"gid"`
	CanonicalHex    string `json:"canonicalHex"`
}

func readGIDSignatureVector(t *testing.T) gidSignatureVector {
	t.Helper()
	data, err := os.ReadFile("../../testdata/spec/golden/gid-signature.json")
	if err != nil {
		t.Fatal(err)
	}
	var v gidSignatureVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func docsVectorKeys(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	v := readGIDSignatureVector(t)
	privBlock, _ := pem.Decode([]byte(v.PrivateKeyPkcs8))
	priv, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	pubBlock, _ := pem.Decode([]byte(v.PublicKeySpki))
	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	return priv.(*ecdsa.PrivateKey), pub.(*ecdsa.PublicKey)
}

// TestGIDDocsTestVector pins the spec's GID signature vector: its canonical
// bytes, its signature, and a fresh signature over them.
func TestGIDDocsTestVector(t *testing.T) {
	priv, pub := docsVectorKeys(t)
	v := readGIDSignatureVector(t)
	g := v.GID

	if got := hex.EncodeToString(canonicalGIDPayload(g.Partner, g.User, g.Bet)); got != v.CanonicalHex {
		t.Errorf("canonical bytes:\n got %s\nwant %s", got, v.CanonicalHex)
	}
	if err := VerifyGID(&g, pub); err != nil {
		t.Errorf("VerifyGID rejects the published signature: %v", err)
	}
	built, err := BuildGID(g.Partner, g.User, g.Bet, priv)
	if err != nil {
		t.Fatalf("BuildGID: %v", err)
	}
	if err := VerifyGID(built, pub); err != nil {
		t.Errorf("VerifyGID rejects a signature BuildGID made with the published key: %v", err)
	}
}

// TestVerifyGID_CanonicalSignatureOnly pins that VerifyGID refuses every form of
// a valid signature but unpadded base64url, as BoostX does.
func TestVerifyGID_CanonicalSignatureOnly(t *testing.T) {
	_, pub := docsVectorKeys(t)
	vector := readGIDSignatureVector(t).GID
	sig := vector.Signature

	for name, bad := range map[string]string{
		"padded":          sig + "==",
		"standard base64": strings.NewReplacer("-", "+", "_", "/").Replace(sig),
		"line break":      sig[:40] + "\n" + sig[40:],
		"stray last bits": sig[:85] + "h",
	} {
		g := vector
		g.Signature = bad
		err := VerifyGID(&g, pub)
		if !errors.Is(err, ErrInvalidSignature) || !errors.Is(err, ErrInvalidGID) {
			t.Errorf("%s: expected ErrInvalidSignature and ErrInvalidGID, got %v", name, err)
		}
	}
}
