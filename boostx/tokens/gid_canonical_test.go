package tokens

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

// TestCanonicalGIDPayloadMatchesJSONStringify pins the GID signing bytes against the
// encoder BoostX actually verifies with: JavaScript's JSON.stringify. The `want` values
// were produced by real Node, so they are evidence, not a restatement of the package.
// Printable characters appear literally, checkable by eye; invisible ones (C0 controls,
// U+2028/U+2029) are written as escapes. See canonicalGIDPayload for why encoding/json
// cannot produce these bytes and why only this table can catch a divergence.
func TestCanonicalGIDPayloadMatchesJSONStringify(t *testing.T) {
	tests := []struct {
		name    string
		partner string
		user    string
		bet     string
		want    string
	}{
		{
			name:    "plain",
			partner: "acme",
			user:    "u1",
			bet:     "b1",
			want:    `{"partner":"acme","user":"u1","bet":"b1"}`,
		},
		{
			name:    "ampersand",
			partner: "acme&co",
			user:    "u&1",
			bet:     "b&1",
			want:    `{"partner":"acme&co","user":"u&1","bet":"b&1"}`,
		},
		{
			name:    "angle_brackets",
			partner: "a<b>c",
			user:    "u<1>",
			bet:     "b>2",
			want:    `{"partner":"a<b>c","user":"u<1>","bet":"b>2"}`,
		},
		{
			name:    "quote_and_backslash",
			partner: `a"b`,
			user:    `u\1`,
			bet:     `b"2`,
			want:    `{"partner":"a\"b","user":"u\\1","bet":"b\"2"}`,
		},
		{
			// Raw-string want: the escape text JSON.stringify emits, not the characters.
			name:    "control_chars",
			partner: "a\nb",
			user:    "u\tv",
			bet:     "b\r",
			want:    `{"partner":"a\nb","user":"u\tv","bet":"b\r"}`,
		},
		{
			// Interpreted-string want: JSON.stringify leaves U+2028/U+2029 literal.
			name:    "line_separators",
			partner: "a\u2028b",
			user:    "u\u2029v",
			bet:     "bet",
			want:    "{\"partner\":\"a\u2028b\",\"user\":\"u\u2029v\",\"bet\":\"bet\"}",
		},
		{
			name:    "other_c0",
			partner: "a\u0001b",
			user:    "u\u001fv",
			bet:     "b",
			want:    `{"partner":"a\u0001b","user":"u\u001fv","bet":"b"}`,
		},
		{
			name:    "cyrillic",
			partner: "акме",
			user:    "пол",
			bet:     "ст",
			want:    `{"partner":"акме","user":"пол","bet":"ст"}`,
		},
		{
			name:    "astral",
			partner: "a😀b",
			user:    "u😀",
			bet:     "b",
			want:    `{"partner":"a😀b","user":"u😀","bet":"b"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(canonicalGIDPayload(tt.partner, tt.user, tt.bet))
			if got != tt.want {
				t.Errorf("canonical payload diverges from JSON.stringify\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

// TestGIDRoundTripSurvivesHTMLSensitiveCharacters checks ids with the characters
// encoding/json escapes and JSON.stringify does not verify end to end. Build and verify share the encoder, so only the pinned
// table above — not this test — can catch an encoding regression.
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

// The GID signature test vector published in the partner docs (GID and
// GamePassJWT, "Signature test vector"). The key pair is a published test pair,
// never a real partner key.
const (
	docsVectorPrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgg+yiWqYEEfonSG9S
9J2fCoWpQen4RwVCwp5oLdWsItChRANCAASlvj4S8JQ0v8W5mCVOJ+45YrVtQh9i
sIIlhM8pV3j730ArA+TEyBnLuI3wleeclUDC7QSFiUDz6XVs+ideI5Qf
-----END PRIVATE KEY-----`
	docsVectorPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpb4+EvCUNL/FuZglTifuOWK1bUIf
YrCCJYTPKVd4+99AKwPkxMgZy7iN8JXnnJVAwu0EhYlA8+l1bPonXiOUHw==
-----END PUBLIC KEY-----`
	docsVectorHex = "7b22706172746e6572223a22706172746e65722d78797a22" +
		"2c2275736572223a22757365722f3c34323e2653c3b872656e22" +
		"2c22626574223a22626574e280a8e280a95c6e31227d"
)

var docsVectorGID = GID{
	Partner:   "partner-xyz",
	User:      "user/<42>&Søren",
	Bet:       "bet\u2028\u2029\n1",
	Signature: "ZVsIq0cnvphruOl9xOsRNY0wjyvCKwCxhAOYNNgwO5f1Fa_vKaXRJvPtW39gXJgoFoKaBpdm4ko5vT8DEor-Ag",
}

func docsVectorKeys(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	privBlock, _ := pem.Decode([]byte(docsVectorPrivateKey))
	priv, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	pubBlock, _ := pem.Decode([]byte(docsVectorPublicKey))
	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	return priv.(*ecdsa.PrivateKey), pub.(*ecdsa.PublicKey)
}

// TestGIDDocsTestVector pins the GID signature test vector the partner docs
// publish: its canonical bytes, its signature, and a fresh signature over them.
func TestGIDDocsTestVector(t *testing.T) {
	priv, pub := docsVectorKeys(t)
	g := docsVectorGID

	if got := hex.EncodeToString(canonicalGIDPayload(g.Partner, g.User, g.Bet)); got != docsVectorHex {
		t.Errorf("canonical bytes:\n got %s\nwant %s", got, docsVectorHex)
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
	sig := docsVectorGID.Signature

	for name, bad := range map[string]string{
		"padded":          sig + "==",
		"standard base64": strings.NewReplacer("-", "+", "_", "/").Replace(sig),
		"line break":      sig[:40] + "\n" + sig[40:],
		"stray last bits": sig[:85] + "h",
	} {
		g := docsVectorGID
		g.Signature = bad
		err := VerifyGID(&g, pub)
		if !errors.Is(err, ErrInvalidSignature) || !errors.Is(err, ErrInvalidGID) {
			t.Errorf("%s: expected ErrInvalidSignature and ErrInvalidGID, got %v", name, err)
		}
	}
}
