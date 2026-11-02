package tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"
)

func generateTestKey(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

// signRaw signs header and payload JSON text exactly as given, for tokens
// SignJWT cannot produce.
func signRaw(t *testing.T, key *ecdsa.PrivateKey, header, payload string) string {
	t.Helper()
	input := base64URLEncode([]byte(header)) + "." + base64URLEncode([]byte(payload))
	sig, err := signES256(key, []byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64URLEncode(sig)
}

func generateCurveKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return privateKey
}

// TestUnusableKeys pins that a key that is nil, zero-valued or off P-256, or a
// private key whose signing fails (D=0), is refused with ErrInvalidPrivateKey
// or ErrInvalidPublicKey, never with a panic or a token BoostX refuses.
func TestUnusableKeys(t *testing.T) {
	zeroD := *generateCurveKey(t, elliptic.P256())
	zeroD.D = big.NewInt(0)
	privateKeys := map[string]*ecdsa.PrivateKey{
		"nil":        nil,
		"zero value": {},
		"P-224":      generateCurveKey(t, elliptic.P224()),
		"P-384":      generateCurveKey(t, elliptic.P384()),
		"P-521":      generateCurveKey(t, elliptic.P521()),
		"D=0":        &zeroD,
	}
	for name, key := range privateKeys {
		if _, err := SignJWT(struct{}{}, key); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Errorf("SignJWT, %s: expected ErrInvalidPrivateKey, got %v", name, err)
		}
		if _, err := BuildGID("partner", "user", "bet", key); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Errorf("BuildGID, %s: expected ErrInvalidPrivateKey, got %v", name, err)
		}
	}

	privateKey, _ := generateTestKey(t)
	token, _ := SignJWT(struct{}{}, privateKey)
	gid, _ := BuildGID("partner", "user", "bet", privateKey)
	publicKeys := map[string]*ecdsa.PublicKey{
		"nil":        nil,
		"zero value": {},
		"P-384":      &generateCurveKey(t, elliptic.P384()).PublicKey,
	}
	for name, key := range publicKeys {
		var claims struct{}
		if err := ParseJWT(token, &claims, key); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("ParseJWT, %s: expected ErrInvalidPublicKey, got %v", name, err)
		}
		if err := VerifyGID(gid, key); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("VerifyGID, %s: expected ErrInvalidPublicKey, got %v", name, err)
		}
	}

	if got := VerifyKeysReason(ErrInvalidPublicKey); got != VerifyKeysReasonSignature {
		t.Errorf("VerifyKeysReason(ErrInvalidPublicKey) = %q, want %q", got, VerifyKeysReasonSignature)
	}
}

// TestMalformedKeyObjects pins that a P-256 key missing its scalar or point,
// or whose point is off the curve, is a key error rather than a panic, and that
// such a key in a partner key list is skipped.
func TestMalformedKeyObjects(t *testing.T) {
	good, goodPub := generateTestKey(t)
	p := elliptic.P256().Params().P
	withPoint := func(x, y *big.Int) *ecdsa.PublicKey {
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	}
	publicKeys := map[string]*ecdsa.PublicKey{
		"X nil":          withPoint(nil, goodPub.Y),
		"Y nil":          withPoint(goodPub.X, nil),
		"X=Y=1":          withPoint(big.NewInt(1), big.NewInt(1)),
		"infinity":       withPoint(big.NewInt(0), big.NewInt(0)),
		"X out of range": withPoint(new(big.Int).Add(goodPub.X, p), goodPub.Y),
	}
	privateKeys := map[string]*ecdsa.PrivateKey{
		"D nil":        {PublicKey: *goodPub},
		"X and Y nil":  {PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}, D: good.D},
		"D = N":        {PublicKey: *goodPub, D: elliptic.P256().Params().N},
		"D negative":   {PublicKey: *goodPub, D: big.NewInt(-1)},
		"only a curve": {PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}},
	}

	token, _ := SignJWT(struct{}{}, good)
	gid, _ := BuildGID("partner", "user", "bet", good)
	booster := signRaw(t, good, `{"alg":"ES256"}`,
		`{"booster":{"gid":`+gidJSON(gid)+`,"round":1,"boost":1.5,"final":false,"jackpot":false},"iat":0}`)
	for name, key := range publicKeys {
		var claims struct{}
		if err := ParseJWT(token, &claims, key); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("ParseJWT, %s: expected ErrInvalidPublicKey, got %v", name, err)
		}
		if err := VerifyGID(gid, key); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("VerifyGID, %s: expected ErrInvalidPublicKey, got %v", name, err)
		}
		if _, err := ParseBoosterTokenWithKeys(booster, goodPub, []*ecdsa.PublicKey{key}); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("ParseBoosterTokenWithKeys [%s]: expected ErrInvalidPublicKey, got %v", name, err)
		}
		if _, err := ParseBoosterTokenWithKeys(booster, goodPub, []*ecdsa.PublicKey{key, goodPub}); err != nil {
			t.Errorf("ParseBoosterTokenWithKeys [%s, good]: expected the token to verify, got %v", name, err)
		}
		if _, err := ParseBoosterTokenWithKeys(booster, key, []*ecdsa.PublicKey{goodPub}); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("ParseBoosterTokenWithKeys, BoostX key %s: expected ErrInvalidPublicKey, got %v", name, err)
		}
	}
	for name, key := range privateKeys {
		if _, err := SignJWT(struct{}{}, key); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Errorf("SignJWT, %s: expected ErrInvalidPrivateKey, got %v", name, err)
		}
		if _, err := BuildGID("partner", "user", "bet", key); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Errorf("BuildGID, %s: expected ErrInvalidPrivateKey, got %v", name, err)
		}
	}
}

// TestPrivateKeyCheckedFirst pins that every builder reports an unusable
// private key before any parameter, whatever else is wrong.
func TestPrivateKeyCheckedFirst(t *testing.T) {
	bad := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}}
	for _, key := range []*ecdsa.PrivateKey{nil, bad, generateCurveKey(t, elliptic.P384())} {
		errs := map[string]error{}
		_, errs["CreateGamePassToken"] = CreateGamePassToken(key, GamePassParams{})
		_, errs["CreateSettlementToken"] = CreateSettlementToken(key, SettlementParams{})
		_, errs["BuildGID"] = BuildGID("", "", "", key)
		_, errs["CreateVerifyKeysRequestToken"] = CreateVerifyKeysRequestToken(key, "", 0)
		_, errs["CreateVerifyKeysResponseToken"] = CreateVerifyKeysResponseToken(key, BoostxIdentity, 0)
		for name, err := range errs {
			if !errors.Is(err, ErrInvalidPrivateKey) || errors.Is(err, ErrMissingClaim) || errors.Is(err, ErrInvalidClaim) {
				t.Errorf("%s: expected ErrInvalidPrivateKey alone, got %v", name, err)
			}
		}
	}
	good, _ := generateTestKey(t)
	if _, err := CreateGamePassToken(good, GamePassParams{}); !errors.Is(err, ErrMissingClaim) {
		t.Errorf("a usable key with no params: expected ErrMissingClaim, got %v", err)
	}
}

// gidJSON returns gid as the JSON object a token carries.
func gidJSON(gid *GID) string {
	b, _ := json.Marshal(gid)
	return string(b)
}

// TestParseJWT_Header pins that only the exact members alg and crit are read:
// alg must be the JSON string "ES256" and crit must be absent, each a
// signature failure; a header that is not one JSON object in valid UTF-8 is a
// malformed token, not a signature failure; every other member is ignored.
func TestParseJWT_Header(t *testing.T) {
	key, pub := generateTestKey(t)
	parse := func(header string) error {
		var claims struct{}
		return ParseJWT(signRaw(t, key, header, `{}`), &claims, pub)
	}

	for _, header := range []string{
		`{"alg":"ES256"}`,
		`{"alg":"ES256","typ":"JWT"}`,
		`{"alg":"ES256","typ":1}`,
		`{"alg":"ES256","typ":{"x":1},"kid":7}`,
		`{"alg":"ES256","typ":["JWT"],"kid":true}`,
		`{"alg":"ES256","typ":false,"kid":{}}`,
		`{"alg":"ES256","TYP":{"x":1}}`,
		`{"alg":"ES256","kid":[1],"x5u":null,"b64":false}`,
		`{"alg":"none","alg":"ES256"}`,
		` {"alg":"ES256"} `,
	} {
		if err := parse(header); err != nil {
			t.Errorf("header %s: expected the token to verify, got %v", header, err)
		}
	}

	for _, header := range []string{
		`{}`,
		`{"ALG":"ES256"}`,
		`{"Alg":"ES256"}`,
		`{"alg":"es256"}`,
		`{"alg":"none"}`,
		`{"alg":1}`,
		`{"alg":null}`,
		`{"alg":true}`,
		`{"alg":{}}`,
		`{"alg":["ES256"]}`,
		`{"alg":"ES256","alg":"none"}`,
		`{"alg":"ES256","crit":[]}`,
		`{"alg":"ES256","crit":["exp"]}`,
		`{"alg":"ES256","crit":null}`,
		`{"alg":"ES256","crit":"x"}`,
	} {
		if err := parse(header); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("header %s: expected ErrInvalidSignature, got %v", header, err)
		}
	}

	for _, header := range []string{
		`null`,
		`[]`,
		`"ES256"`,
		`1`,
		`true`,
		``,
		`{"alg":"ES256"} {}`,
		`{"alg":"ES256"`,
		"{\"alg\":\"ES256\",\"kid\":\"\xff\"}", // invalid UTF-8
		"\xef\xbb\xbf{\"alg\":\"ES256\"}",      // byte order mark
	} {
		if err := parse(header); err == nil || errors.Is(err, ErrInvalidSignature) {
			t.Errorf("header %q: expected a malformed-token error, got %v", header, err)
		}
	}
}

// TestParseJWT_Segments pins canonical unpadded base64url for each segment: a
// header or payload segment that is not is a malformed token, a signature
// segment that is not, or is not 64 bytes, is a signature failure.
func TestParseJWT_Segments(t *testing.T) {
	key, pub := generateTestKey(t)
	token := signRaw(t, key, `{"alg":"ES256"} `, `{"sub":"x"}`) // a 16-byte header leaves 4 spare bits
	parts := strings.Split(token, ".")
	parse := func(h, p, s string) error {
		var claims struct{}
		return ParseJWT(h+"."+p+"."+s, &claims, pub)
	}
	// strayBits sets the unused low bits of the last character of seg.
	strayBits := func(seg string) string {
		i := strings.IndexByte(base64URLAlphabet, seg[len(seg)-1])
		return seg[:len(seg)-1] + string(base64URLAlphabet[i|1])
	}

	if err := parse(parts[0], parts[1], parts[2]); err != nil {
		t.Fatalf("the canonical token: %v", err)
	}
	for name, err := range map[string]error{
		"padded header":           parse(parts[0]+"==", parts[1], parts[2]),
		"header with a line feed": parse(parts[0][:4]+"\n"+parts[0][4:], parts[1], parts[2]),
		"header with CR LF":       parse(parts[0][:4]+"\r\n"+parts[0][4:], parts[1], parts[2]),
		"leading space":           parse(" "+parts[0], parts[1], parts[2]),
		"header stray bits":       parse(strayBits(parts[0]), parts[1], parts[2]),
		"header length 1 mod 4":   parse(parts[0]+"AAA", parts[1], parts[2]),
	} {
		if err == nil || errors.Is(err, ErrInvalidSignature) {
			t.Errorf("%s: expected a malformed-token error, got %v", name, err)
		}
	}
	for name, err := range map[string]error{
		"padded signature":           parse(parts[0], parts[1], parts[2]+"=="),
		"signature with a line feed": parse(parts[0], parts[1], parts[2][:4]+"\n"+parts[2][4:]),
		"trailing newline":           parse(parts[0], parts[1], parts[2]+"\n"),
		"trailing space":             parse(parts[0], parts[1], parts[2]+" "),
		"signature stray bits":       parse(parts[0], parts[1], strayBits(parts[2])),
		"plus":                       parse(parts[0], parts[1], "+"+parts[2][1:]),
		"slash":                      parse(parts[0], parts[1], "/"+parts[2][1:]),
		"63 bytes":                   parse(parts[0], parts[1], base64URLEncode(make([]byte, 63))),
		"65 bytes":                   parse(parts[0], parts[1], base64URLEncode(make([]byte, 65))),
		"empty signature":            parse(parts[0], parts[1], ""),
		"bang":                       parse(parts[0], parts[1], "!"+parts[2][1:]),
	} {
		if !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("%s: expected ErrInvalidSignature, got %v", name, err)
		}
	}
	var claims struct{}
	if err := ExtractJWTClaims(parts[0]+"."+parts[1]+"==."+parts[2], &claims); err == nil {
		t.Error("ExtractJWTClaims, padded payload: expected an error")
	}
}

const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// TestParseJWT_Payload pins that a payload must be one JSON object in valid
// UTF-8 with no byte order mark, JSON whitespace around it allowed.
func TestParseJWT_Payload(t *testing.T) {
	key, pub := generateTestKey(t)
	for _, payload := range []string{"{}", " \t\r\n{\"sub\":\"x\"}\n "} {
		var claims struct{}
		if err := ParseJWT(signRaw(t, key, `{"alg":"ES256"}`, payload), &claims, pub); err != nil {
			t.Errorf("payload %q: expected the token to verify, got %v", payload, err)
		}
	}
	for _, payload := range []string{
		"null", "[]", "1", `"x"`, "true", "", "{} {}", "{}x",
		"{\"sub\":\"\xff\"}",     // invalid UTF-8
		"{\"sub\":\"\xc0\xaf\"}", // overlong
		"\xef\xbb\xbf{}",         // byte order mark
	} {
		token := signRaw(t, key, `{"alg":"ES256"}`, payload)
		var claims struct{}
		if err := ParseJWT(token, &claims, pub); err == nil || errors.Is(err, ErrInvalidSignature) {
			t.Errorf("ParseJWT, payload %q: expected a malformed-token error, got %v", payload, err)
		}
		if err := ExtractJWTClaims(token, &claims); err == nil {
			t.Errorf("ExtractJWTClaims, payload %q: expected an error", payload)
		}
	}
}

func TestSignAndParseJWT(t *testing.T) {
	privateKey, publicKey := generateTestKey(t)

	claims := struct {
		Sub string `json:"sub"`
		RegisteredClaims
	}{
		Sub: "test-subject",
		RegisteredClaims: RegisteredClaims{
			IssuedAt: time.Now().Unix(),
		},
	}

	token, err := SignJWT(claims, privateKey)
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}

	if token == "" {
		t.Fatal("SignJWT returned empty token")
	}

	var parsed struct {
		Sub string `json:"sub"`
		RegisteredClaims
	}
	err = ParseJWT(token, &parsed, publicKey)
	if err != nil {
		t.Fatalf("ParseJWT failed: %v", err)
	}

	if parsed.Sub != "test-subject" {
		t.Errorf("expected sub=%q, got %q", "test-subject", parsed.Sub)
	}
}

func TestParseJWT_InvalidSignature(t *testing.T) {
	privateKey, _ := generateTestKey(t)
	_, wrongPublicKey := generateTestKey(t)

	claims := struct {
		Sub string `json:"sub"`
	}{
		Sub: "test-subject",
	}

	token, err := SignJWT(claims, privateKey)
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}

	var parsed struct {
		Sub string `json:"sub"`
	}
	err = ParseJWT(token, &parsed, wrongPublicKey)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestParseJWT_InvalidFormat(t *testing.T) {
	_, publicKey := generateTestKey(t)

	testCases := []string{
		"",
		"not.a.token",
		"only.two",
		"too.many.parts.here",
	}

	for _, tc := range testCases {
		var parsed struct{}
		err := ParseJWT(tc, &parsed, publicKey)
		if err == nil {
			t.Errorf("expected error for token %q, got nil", tc)
		}
	}
}

func TestExtractJWTClaims(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	claims := struct {
		Partner string `json:"partner"`
		User    string `json:"user"`
	}{
		Partner: "partner-123",
		User:    "user-456",
	}

	token, err := SignJWT(claims, privateKey)
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}

	var extracted struct {
		Partner string `json:"partner"`
		User    string `json:"user"`
	}
	err = ExtractJWTClaims(token, &extracted)
	if err != nil {
		t.Fatalf("ExtractJWTClaims failed: %v", err)
	}

	if extracted.Partner != "partner-123" {
		t.Errorf("expected partner=%q, got %q", "partner-123", extracted.Partner)
	}
	if extracted.User != "user-456" {
		t.Errorf("expected user=%q, got %q", "user-456", extracted.User)
	}
}

// TestIllFormedUnicodeInTokens pins that a header or payload escaping a lone
// surrogate, or carrying invalid UTF-8, is a malformed token in extract and
// parse alike, never a signature or GID failure, while an escaped pair, an
// escaped backslash before u and plain UTF-8 are read as written.
func TestIllFormedUnicodeInTokens(t *testing.T) {
	partnerPriv, partnerPub := generateTestKey(t)
	boostxPriv, boostxPub := generateTestKey(t)
	bs := string(rune(92))
	u := func(hex string) string { return bs + "u" + hex } // a JSON u escape
	gid := func(user, wireUser string) string {
		g, err := BuildGID("partner", user, "bet", partnerPriv)
		if err != nil {
			t.Fatal(err)
		}
		return `{"partner":"partner","user":"` + wireUser + `","bet":"bet","signature":"` + g.Signature + `"}`
	}
	const fields = `"round":1,"boost":1.5,"final":false,"jackpot":false`
	booster := func(header, gid string) string {
		return signRaw(t, boostxPriv, header, `{"booster":{"gid":`+gid+`,`+fields+`},"iat":0}`)
	}
	checkBet := func(gid string) string {
		return signRaw(t, boostxPriv, `{"alg":"ES256"}`, `{"checkbet":{"gid":`+gid+`},"iat":0}`)
	}
	now := strconv.FormatInt(time.Now().Unix(), 10)
	verifyKeys := func(text string) string {
		return signRaw(t, boostxPriv, `{"alg":"ES256"}`,
			`{"iss":"boostx","aud":"partner","iat":`+now+`,"verifyKeys":{"nonce":5},"note":"`+text+`"}`)
	}
	const alg = `{"alg":"ES256"}`

	for _, bad := range []string{
		u("d800"), u("D800"), u("dbff"), u("dc00"), u("DFFF"),
		"a" + u("d800") + "b",
		u("d800") + u("0041"),
		u("d800") + u("d800"),
		u("dc00") + u("d800"),
		u("d800") + "x" + u("dc00"),
		u("d83d") + u("de00") + u("dc00"),
		u("d800") + bs + "n",
		string([]byte{0xff}),             // invalid UTF-8
		string([]byte{0xed, 0xa0, 0x80}), // a surrogate encoded as UTF-8
	} {
		errs := map[string]error{}
		_, errs["parse booster"] = ParseBoosterToken(booster(alg, gid("x", bad)), boostxPub, partnerPub)
		_, errs["extract booster"] = ExtractBoosterPartner(booster(alg, gid("x", bad)))
		_, errs["parse booster, header"] = ParseBoosterToken(booster(`{"alg":"ES256","kid":"`+bad+`"}`, gid("x", "x")), boostxPub, partnerPub)
		for name, err := range errs {
			if !errors.Is(err, ErrInvalidBooster) || errors.Is(err, ErrInvalidSignature) || errors.Is(err, ErrInvalidGID) {
				t.Errorf("%s %q: expected ErrInvalidBooster alone, got %v", name, bad, err)
			}
		}
		errs = map[string]error{}
		_, errs["parse checkbet"] = ParseCheckBetToken(checkBet(gid("x", bad)), boostxPub, partnerPub)
		_, errs["extract checkbet"] = ExtractCheckBetPartner(checkBet(gid("x", bad)))
		for name, err := range errs {
			if !errors.Is(err, ErrInvalidCheckBet) || errors.Is(err, ErrInvalidSignature) || errors.Is(err, ErrInvalidGID) {
				t.Errorf("%s %q: expected ErrInvalidCheckBet alone, got %v", name, bad, err)
			}
		}
		errs = map[string]error{}
		_, errs["parse verify-keys"] = ParseVerifyKeysRequestToken(verifyKeys(bad), boostxPub, "partner", 0)
		_, errs["extract verify-keys"] = ExtractVerifyKeysRequestPartner(verifyKeys(bad))
		for name, err := range errs {
			if err == nil || VerifyKeysReason(err) != VerifyKeysReasonShape {
				t.Errorf("%s %q: expected reason shape, got %v", name, bad, err)
			}
		}
		var claims struct{}
		if err := ParseJWT(signRaw(t, boostxPriv, `{"alg":"ES256","kid":"`+bad+`"}`, `{}`), &claims, boostxPub); err == nil || errors.Is(err, ErrInvalidSignature) {
			t.Errorf("ParseJWT, header %q: expected a malformed-token error, got %v", bad, err)
		}
		if err := ExtractJWTClaims(signRaw(t, boostxPriv, alg, `{"sub":"`+bad+`"}`), &claims); err == nil {
			t.Errorf("ExtractJWTClaims, payload %q: expected an error", bad)
		}
	}

	for _, tc := range []struct{ user, wire string }{
		{"😀", u("d83d") + u("de00")},
		{"😀", u("D83D") + u("DE00")},
		{"😀", "😀"},
		{"A", u("0041")},
		{bs + "ud800", bs + bs + "ud800"},
		{bs, bs + bs},
	} {
		b, err := ParseBoosterToken(booster(alg, gid(tc.user, tc.wire)), boostxPub, partnerPub)
		if err != nil || b.User != tc.user {
			t.Errorf("parse booster %q: expected user %q, got %+v, %v", tc.wire, tc.user, b, err)
		}
		if _, err := ExtractBoosterPartner(booster(alg, gid(tc.user, tc.wire))); err != nil {
			t.Errorf("extract booster %q: %v", tc.wire, err)
		}
		if _, err := ParseCheckBetToken(checkBet(gid(tc.user, tc.wire)), boostxPub, partnerPub); err != nil {
			t.Errorf("parse checkbet %q: %v", tc.wire, err)
		}
		if _, err := ParseVerifyKeysRequestToken(verifyKeys(tc.wire), boostxPub, "partner", 0); err != nil {
			t.Errorf("parse verify-keys %q: %v", tc.wire, err)
		}
	}
}
