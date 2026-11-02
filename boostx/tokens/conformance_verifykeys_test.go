package tokens_test

// Runner for the VERIFYKEYS group of the shared conformance vectors in
// testdata/spec (format: FORMAT.md there). It implements the operations
// that group uses: the verify-keys builders, the request extraction, both
// parsers, and http.serve on the verify-keys endpoint with the default bet
// store. Anything else the group does not use fails the case as unsupported.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/client"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/handlers"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

const (
	confVerifykeysDir      = "../../testdata/spec/"
	confVerifykeysAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

var (
	confVerifykeysPlaceholderRE = regexp.MustCompile(`\$\{([^}]*)\}`)
	confVerifykeysExactRE       = regexp.MustCompile(`^\$\{([^}]*)\}$`)
	confVerifykeysTimeRE        = regexp.MustCompile(`^(nowMs|now)(?:([+-])(\d+))?$`)
	confVerifykeysFieldRE       = regexp.MustCompile(`^[A-Za-z0-9_.]*`)

	confVerifykeysCategories = []struct {
		name string
		err  error
	}{
		{"invalid_private_key", tokens.ErrInvalidPrivateKey},
		{"invalid_public_key", tokens.ErrInvalidPublicKey},
		{"invalid_booster", tokens.ErrInvalidBooster},
		{"invalid_checkbet", tokens.ErrInvalidCheckBet},
		{"invalid_verify_keys", tokens.ErrInvalidVerifyKeys},
		{"invalid_gid", tokens.ErrInvalidGID},
		{"invalid_signature", tokens.ErrInvalidSignature},
		{"missing_claim", tokens.ErrMissingClaim},
		{"invalid_claim", tokens.ErrInvalidClaim},
		{"unknown_partner", keys.ErrUnknownPartner},
	}

	confVerifykeysJWTMember = map[string]string{
		"set-boost": "boosterJWT", "check-bet": "checkbetJWT", "verify-keys": "verifyKeysJWT",
	}
)

type confVerifykeysCase struct {
	Name          string         `json:"name"`
	Op            string         `json:"op"`
	Input         map[string]any `json:"input"`
	Sigs          map[string]any `json:"sigs"`
	Want          map[string]any `json:"want"`
	WantZeroValue map[string]any `json:"wantZeroValue"`
	Needs         []string       `json:"needs"`
}

type confVerifykeysKeys struct {
	priv map[string]*ecdsa.PrivateKey // by key name, plus "@unusable"
	pub  map[string]*ecdsa.PublicKey
	sigs map[string]string // the predefined GID signatures gid and gid2
}

type confVerifykeysRun struct {
	t   *testing.T
	k   *confVerifykeysKeys
	c   confVerifykeysCase
	now int64
}

func TestConformanceVerifykeys(t *testing.T) {
	k := confVerifykeysLoadKeys(t)
	var file struct {
		Group string               `json:"group"`
		Cases []confVerifykeysCase `json:"cases"`
	}
	confVerifykeysReadJSON(t, "verifykeys.json", &file)
	if file.Group != "verifykeys" || len(file.Cases) == 0 {
		t.Fatalf("unexpected vector file: group %q, %d cases", file.Group, len(file.Cases))
	}
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if confSkipNeeds(t, c.Needs) {
				return
			}
			(&confVerifykeysRun{t: t, k: k, c: c, now: time.Now().Unix()}).run()
		})
	}
}

func confVerifykeysReadJSON(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(confVerifykeysDir + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func confVerifykeysLoadKeys(t *testing.T) *confVerifykeysKeys {
	var tk struct {
		Keys          map[string]map[string]string `json:"keys"`
		GIDSignatures []struct {
			Key, Partner, User, Bet, Signature string
		} `json:"gidSignatures"`
	}
	confVerifykeysReadJSON(t, "testkeys.json", &tk)
	k := &confVerifykeysKeys{
		priv: map[string]*ecdsa.PrivateKey{},
		pub:  map[string]*ecdsa.PublicKey{},
		sigs: map[string]string{},
	}
	for _, n := range []string{"partner", "partner2", "boostx", "other"} {
		var err error
		if k.priv[n], err = keys.LoadPrivateKeyFromPEM([]byte(tk.Keys[n]["pkcs8"])); err != nil {
			t.Fatalf("key %s: %v", n, err)
		}
		if k.pub[n], err = keys.LoadPublicKeyFromPEM([]byte(tk.Keys[n]["spki"])); err != nil {
			t.Fatalf("key %s: %v", n, err)
		}
	}
	// "@unusable" is the P-384 pair, loaded with the platform's own parsers.
	der := func(text string) []byte {
		block, _ := pem.Decode([]byte(text))
		if block == nil {
			t.Fatal("p384: no PEM block")
		}
		return block.Bytes
	}
	priv, err := x509.ParsePKCS8PrivateKey(der(tk.Keys["p384"]["pkcs8"]))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(der(tk.Keys["p384"]["spki"]))
	if err != nil {
		t.Fatal(err)
	}
	k.priv["@unusable"], k.pub["@unusable"] = priv.(*ecdsa.PrivateKey), pub.(*ecdsa.PublicKey)
	for _, g := range tk.GIDSignatures {
		if g.Partner == "acme" && g.User == "u-1" && g.Bet == "b-1" {
			switch g.Key {
			case "partner":
				k.sigs["gid"] = g.Signature
			case "partner2":
				k.sigs["gid2"] = g.Signature
			}
		}
	}
	return k
}

func (r *confVerifykeysRun) run() {
	want := r.c.Want
	if r.c.WantZeroValue != nil {
		want = r.c.WantZeroValue
	}
	in := r.c.Input
	var got map[string]any
	var err error
	switch r.c.Op {
	case "verifykeys.createRequest", "verifykeys.createResponse":
		create, keyName := tokens.CreateVerifyKeysRequestToken, "boostx"
		if r.c.Op == "verifykeys.createResponse" {
			create, keyName = tokens.CreateVerifyKeysResponseToken, "partner"
		}
		key, keyName := r.privKey(keyName)
		partnerID, nonce := r.partnerID(), r.nonce()
		var tok string
		if tok, err = create(key, partnerID, nonce); err == nil {
			got = map[string]any{"payload": r.builderPayload(tok, keyName)}
		}
	case "verifykeys.extractRequest":
		var partner string
		if partner, err = tokens.ExtractVerifyKeysRequestPartner(r.token(in["token"], "boostx")); err == nil {
			got = map[string]any{"partner": partner}
		}
	case "verifykeys.parseRequest":
		tok := r.token(in["token"], "boostx")
		key, _ := r.pubKey("boostx")
		var res *tokens.VerifyKeysRequest
		if res, err = tokens.ParseVerifyKeysRequestToken(tok, key, r.partnerID(), r.window()); err == nil {
			got = map[string]any{"partnerID": res.PartnerID, "nonce": float64(res.Nonce), "iat": float64(res.IssuedAt)}
		}
	case "verifykeys.parseResponse":
		tok := r.token(in["token"], "partner")
		key, _ := r.pubKey("partner")
		var res *tokens.VerifyKeysResponse
		if res, err = tokens.ParseVerifyKeysResponseToken(tok, key, r.partnerID(), r.window()); err == nil {
			got = map[string]any{"partnerID": res.PartnerID, "nonce": float64(res.Nonce), "iat": float64(res.IssuedAt)}
		}
	case "http.serve":
		r.serve(want)
		return
	default:
		r.t.Fatalf("op %q is not supported by the VERIFYKEYS runner", r.c.Op)
	}
	r.checkOutcome(want, got, err)
}

// --- inputs ---

func (r *confVerifykeysRun) privNamed(name string) *ecdsa.PrivateKey {
	k, ok := r.k.priv[name]
	if !ok {
		r.t.Fatalf("unknown private key reference %q", name)
	}
	return k
}

func (r *confVerifykeysRun) pubNamed(name string) *ecdsa.PublicKey {
	k, ok := r.k.pub[name]
	if !ok {
		r.t.Fatalf("unknown public key reference %q", name)
	}
	return k
}

// privKey resolves the case's "key" reference (default def) and returns its name.
func (r *confVerifykeysRun) privKey(def string) (*ecdsa.PrivateKey, string) {
	v, ok := r.c.Input["key"]
	if !ok {
		v = def
	}
	if v == nil {
		return nil, ""
	}
	name, _ := v.(string)
	return r.privNamed(name), name
}

func (r *confVerifykeysRun) pubKey(def string) (*ecdsa.PublicKey, string) {
	v, ok := r.c.Input["key"]
	if !ok {
		v = def
	}
	if v == nil {
		return nil, ""
	}
	name, _ := v.(string)
	return r.pubNamed(name), name
}

func (r *confVerifykeysRun) partnerID() string {
	v, given := r.c.Input["partnerID"]
	switch s := v.(type) {
	case string:
		return s
	case nil:
		if !given {
			return "acme"
		}
		return ""
	case map[string]any:
		if ill, ok := s["$illFormed"].(string); ok && len(s) == 1 {
			return ill + "\xff"
		}
	}
	r.t.Fatalf("unrepresentable input in an untagged case: partnerID %v is not a string", v)
	return ""
}

func confVerifykeysNumber(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case map[string]any:
		switch x["$number"] {
		case "NaN":
			return math.NaN(), true
		case "Infinity":
			return math.Inf(1), true
		case "-Infinity":
			return math.Inf(-1), true
		case "-0":
			return math.Copysign(0, -1), true
		}
	}
	return 0, false
}

// nonce maps the case's nonce to int32: left out or null is 0, anything an
// int32 cannot hold fails the case (FORMAT section 7).
func (r *confVerifykeysRun) nonce() int32 {
	v := r.c.Input["nonce"]
	if v == nil {
		return 0
	}
	f, ok := confVerifykeysNumber(v)
	if !ok || f != math.Trunc(f) || f < math.MinInt32 || f > math.MaxInt32 {
		r.t.Fatalf("unrepresentable input in an untagged case: nonce %v is not an int32", v)
	}
	return int32(f)
}

// window maps windowSeconds to a time.Duration: left out or null is 0. NaN and
// the infinities have no Duration value, so those inputs fail the case.
func (r *confVerifykeysRun) window() time.Duration {
	v := r.c.Input["windowSeconds"]
	if v == nil {
		return 0
	}
	f, ok := confVerifykeysNumber(v)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		r.t.Fatalf("unrepresentable input in an untagged case: windowSeconds %v has no time.Duration value", v)
	}
	return time.Duration(f * 1e9)
}

// --- placeholders ---

func (r *confVerifykeysRun) timeValue(p string) (v, tol int64, ok bool) {
	m := confVerifykeysTimeRE.FindStringSubmatch(p)
	if m == nil {
		return 0, 0, false
	}
	v, tol = r.now, 5
	if m[1] == "nowMs" {
		v, tol = r.now*1000, 5000
	}
	if m[3] != "" {
		n, _ := strconv.ParseInt(m[3], 10, 64)
		if m[2] == "-" {
			n = -n
		}
		v += n
	}
	return v, tol, true
}

func (r *confVerifykeysRun) hexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		r.t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

// expand replaces every placeholder in a text field; tok is the case token for
// ${token}, nil where it is not allowed.
func (r *confVerifykeysRun) expand(s string, tok *string) []byte {
	var out []byte
	last := 0
	for _, m := range confVerifykeysPlaceholderRE.FindAllStringSubmatchIndex(s, -1) {
		out = append(out, s[last:m[0]]...)
		out = append(out, r.text(s[m[2]:m[3]], tok)...)
		last = m[1]
	}
	return append(out, s[last:]...)
}

func (r *confVerifykeysRun) text(p string, tok *string) []byte {
	if v, _, ok := r.timeValue(p); ok {
		return strconv.AppendInt(nil, v, 10)
	}
	name, arg, _ := strings.Cut(p, ":")
	switch {
	case p == "$":
		return []byte("$")
	case name == "hex":
		return r.hexBytes(arg)
	case p == "token" && tok != nil:
		return []byte(confVerifykeysEscape(*tok))
	case p == "gid":
		return r.gidJSON("gid")
	case name == "gid":
		return r.gidJSON(arg)
	case name == "sig":
		return []byte(r.sig(arg))
	}
	r.t.Fatalf("placeholder ${%s} is not supported here", p)
	return nil
}

// confVerifykeysEscape JSON-string-escapes s without quotes: '"', '\' and C0
// controls, nothing else.
func confVerifykeysEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20:
			fmt.Fprintf(&b, `\u%04x`, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func (r *confVerifykeysRun) sig(name string) string {
	if _, ok := r.c.Sigs[name]; ok {
		r.t.Fatalf("case-defined sigs are not supported by the VERIFYKEYS runner")
	}
	s, ok := r.k.sigs[name]
	if !ok {
		r.t.Fatalf("unknown GID signature %q", name)
	}
	return s
}

func (r *confVerifykeysRun) gidJSON(name string) []byte {
	b, err := json.Marshal(struct {
		Partner   string `json:"partner"`
		User      string `json:"user"`
		Bet       string `json:"bet"`
		Signature string `json:"signature"`
	}{"acme", "u-1", "b-1", r.sig(name)})
	if err != nil {
		r.t.Fatal(err)
	}
	return b
}

// --- token specs ---

func (r *confVerifykeysRun) sign(key *ecdsa.PrivateKey, data string) string {
	h := sha256.Sum256([]byte(data))
	sr, ss, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		r.t.Fatal(err)
	}
	sig := make([]byte, 64)
	sr.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

func (r *confVerifykeysRun) token(v any, defKey string) string {
	t := r.t
	spec, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("token spec %v is not an object", v)
	}
	if raw, ok := spec["raw"].(string); ok {
		return string(r.expand(raw, nil))
	}
	header := []byte(`{"alg":"ES256","typ":"JWT"}`)
	if h, ok := spec["headerHex"].(string); ok {
		header = r.hexBytes(h)
	} else if h, ok := spec["header"].(string); ok {
		header = r.expand(h, nil)
	}
	var payload []byte
	if p, ok := spec["payloadHex"].(string); ok {
		payload = r.hexBytes(p)
	} else if p, ok := spec["payload"].(string); ok {
		payload = r.expand(p, nil)
	} else {
		t.Fatal("token spec has no payload")
	}
	h := r.transforms(base64.RawURLEncoding.EncodeToString(header), spec["headerSegment"], "segment")
	p := r.transforms(base64.RawURLEncoding.EncodeToString(payload), spec["payloadSegment"], "segment")
	name := defKey
	if k, ok := spec["key"]; ok {
		name, _ = k.(string)
	}
	if name == "@unusable" {
		t.Fatal("the runner signs tokens with P-256 keys only")
	}
	key := r.privNamed(name)
	sig := r.sign(key, h+"."+p)
	sigTr, _ := spec["signature"].([]any)
	for i := 0; i < 64 && slices.Contains(sigTr, any("std-alphabet")) && !strings.ContainsAny(sig, "-_"); i++ {
		sig = r.sign(key, h+"."+p)
	}
	sig = r.transforms(sig, spec["signature"], "signature")
	return r.transforms(h+"."+p+"."+sig, spec["transform"], "token")
}

// transforms applies a list of transforms to a segment, signature or token;
// one that leaves its text unchanged fails the case.
func (r *confVerifykeysRun) transforms(s string, list any, target string) string {
	if list == nil {
		return s
	}
	items, ok := list.([]any)
	if !ok {
		r.t.Fatalf("transforms %v are not a list", list)
	}
	for _, tr := range items {
		out, err := confVerifykeysTransform(s, tr, target)
		if err == nil && out == s {
			err = errors.New("changes nothing")
		}
		if err != nil {
			r.t.Fatalf("transform %v on %s %q: %v", tr, target, s, err)
		}
		s = out
	}
	return s
}

func confVerifykeysTransform(s string, tr any, target string) (string, error) {
	sig, tok := target == "signature", target == "token"
	if name, ok := tr.(string); ok {
		switch {
		case name == "pad" && !tok:
			if len(s)%4 == 0 {
				return s + "====", nil
			}
			return s + strings.Repeat("=", 4-len(s)%4), nil
		case name == "std-alphabet" && !tok:
			return strings.NewReplacer("-", "+", "_", "/").Replace(s), nil
		case name == "trailing-bits" && !tok:
			if len(s)%4 == 0 {
				return "", errors.New("length is a multiple of 4")
			}
			i := strings.IndexByte(confVerifykeysAlphabet, s[len(s)-1])
			if i < 0 || i == 63 {
				return "", errors.New("last character has no successor")
			}
			return s[:len(s)-1] + confVerifykeysAlphabet[i+1:i+2], nil
		case name == "empty" && sig:
			return "", nil
		case name == "zero" && sig:
			return base64.RawURLEncoding.EncodeToString(make([]byte, 64)), nil
		case name == "flip" && sig:
			b, err := base64.RawURLEncoding.Strict().DecodeString(s)
			if err != nil || len(b) == 0 {
				return "", errors.New("signature does not decode")
			}
			b[0] ^= 1
			return base64.RawURLEncoding.EncodeToString(b), nil
		}
		return "", fmt.Errorf("unsupported for a %s", target)
	}
	m, _ := tr.(map[string]any)
	num := func(k string) int { f, _ := m[k].(float64); return int(f) }
	if text, ok := m["insert"].(string); ok {
		at := num("at")
		if at < 0 {
			at += len(s)
		}
		if at < 0 || at > len(s) {
			return "", errors.New("offset out of range")
		}
		return s[:at] + text + s[at:], nil
	}
	if text, ok := m["append"].(string); ok {
		return s + text, nil
	}
	if _, ok := m["truncate"]; ok {
		if n := num("truncate"); n <= len(s) {
			return s[:len(s)-n], nil
		}
		return "", errors.New("truncates past the start")
	}
	if _, ok := m["segments"]; ok && tok {
		parts := strings.Split(s, ".")
		if n := num("segments"); n <= len(parts) {
			return strings.Join(parts[:n], "."), nil
		}
		return "", errors.New("fewer segments than kept")
	}
	return "", fmt.Errorf("unsupported for a %s", target)
}

// builderPayload runs the implicit checks on an accepted builder token and
// returns its decoded payload. Verify-keys payloads carry no gid to verify.
func (r *confVerifykeysRun) builderPayload(tok, keyName string) map[string]any {
	t := r.t
	seg := strings.Split(tok, ".")
	if len(seg) != 3 {
		t.Fatalf("builder token has %d segments: %q", len(seg), tok)
	}
	raw := make([][]byte, 3)
	for i, s := range seg {
		b, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
			t.Fatalf("builder token segment %d is not canonical base64url: %q", i, s)
		}
		raw[i] = b
	}
	var hdr map[string]any
	if json.Unmarshal(raw[0], &hdr) != nil || len(hdr) != 2 || hdr["alg"] != "ES256" || hdr["typ"] != "JWT" {
		t.Errorf("builder header is not exactly alg ES256 and typ JWT: %s", raw[0])
	}
	h := sha256.Sum256([]byte(seg[0] + "." + seg[1]))
	if len(raw[2]) != 64 || !ecdsa.Verify(r.k.pub[keyName], h[:],
		new(big.Int).SetBytes(raw[2][:32]), new(big.Int).SetBytes(raw[2][32:])) {
		t.Errorf("builder signature does not verify with %s", keyName)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw[1], &payload); err != nil {
		t.Fatalf("builder payload: %v", err)
	}
	return payload
}

// --- outcomes ---

func (r *confVerifykeysRun) knownWant(want map[string]any, names ...string) {
	for k := range want {
		if !slices.Contains(names, k) {
			r.t.Fatalf("want member %q is not supported by the VERIFYKEYS runner for %s", k, r.c.Op)
		}
	}
}

func confVerifykeysErrorSet(err error) []string {
	var set []string
	for _, c := range confVerifykeysCategories {
		if errors.Is(err, c.err) {
			set = append(set, c.name)
		}
	}
	var apiErr *client.APIError
	if errors.As(err, &apiErr) {
		set = append(set, "api_error")
	}
	slices.Sort(set)
	return set
}

// confVerifykeysField reads the field an error names: the longest run of
// [A-Za-z0-9_.] after the last "missing required claim: " or "invalid claim value: ".
func confVerifykeysField(msg string) string {
	at, rest := -1, ""
	for _, p := range []string{"missing required claim: ", "invalid claim value: "} {
		if i := strings.LastIndex(msg, p); i > at {
			at, rest = i, msg[i+len(p):]
		}
	}
	return confVerifykeysFieldRE.FindString(rest)
}

func (r *confVerifykeysRun) checkOutcome(want, got map[string]any, err error) {
	t := r.t
	r.knownWant(want, "ok", "error", "field", "reason")
	if wantOK, ok := want["ok"].(map[string]any); ok {
		if err != nil {
			t.Fatalf("want ok %v, got error %v (categories %v)", wantOK, err, confVerifykeysErrorSet(err))
		}
		for name, w := range wantOK {
			if name == "absent" {
				r.checkAbsent(w, got["payload"])
				continue
			}
			g, present := got[name]
			if !present {
				t.Errorf("%s: not in the result %v", name, got)
				continue
			}
			r.match(name, w, g)
		}
		return
	}
	wantErr, ok := want["error"].([]any)
	if !ok {
		t.Fatalf("want has neither ok nor an error list: %v", want)
	}
	if err == nil {
		t.Fatalf("want error %v, got ok %v", wantErr, got)
	}
	var ws []string
	for _, w := range wantErr {
		s, _ := w.(string)
		ws = append(ws, s)
	}
	slices.Sort(ws)
	if gs := confVerifykeysErrorSet(err); !slices.Equal(ws, gs) {
		t.Errorf("error categories: want %v, got %v (%v)", ws, gs, err)
	}
	if f, ok := want["field"]; ok {
		if g := confVerifykeysField(err.Error()); g != f {
			t.Errorf("field: want %v, got %q (%v)", f, g, err)
		}
	}
	if reason, ok := want["reason"]; ok {
		if g := tokens.VerifyKeysReason(err); g != reason {
			t.Errorf("reason: want %v, got %q (%v)", reason, g, err)
		}
	}
}

// match compares only the members want lists; a time expression matches any
// value up to 5 s (5000 ms) after it.
func (r *confVerifykeysRun) match(path string, want, got any) {
	t := r.t
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			t.Errorf("%s: want an object, got %v", path, got)
			return
		}
		for k, wv := range w {
			gv, present := g[k]
			if !present {
				t.Errorf("%s.%s: missing in %v", path, k, got)
				continue
			}
			r.match(path+"."+k, wv, gv)
		}
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			t.Errorf("%s: want %v, got %v", path, want, got)
			return
		}
		for i := range w {
			r.match(fmt.Sprintf("%s[%d]", path, i), w[i], g[i])
		}
	case string:
		if m := confVerifykeysExactRE.FindStringSubmatch(w); m != nil {
			if v, tol, ok := r.timeValue(m[1]); ok {
				g, isNum := got.(float64)
				if !isNum || g < float64(v) || g > float64(v+tol) {
					t.Errorf("%s: want %s (%d..%d), got %v", path, w, v, v+tol, got)
				}
				return
			}
			w = string(r.text(m[1], nil))
		}
		if got != w {
			t.Errorf("%s: want %q, got %v", path, w, got)
		}
	default:
		if got != want {
			t.Errorf("%s: want %v, got %v", path, want, got)
		}
	}
}

func (r *confVerifykeysRun) checkAbsent(paths, payload any) {
	list, _ := paths.([]any)
	for _, p := range list {
		path, _ := p.(string)
		cur, present := payload, true
		for _, part := range strings.Split(path, ".") {
			m, isObj := cur.(map[string]any)
			if cur, present = m[part]; !isObj || !present {
				present = false
				break
			}
		}
		if present {
			r.t.Errorf("absent: %s is present in the payload", path)
		}
	}
}

// --- http.serve ---

type confVerifykeysRole struct {
	pubs []*ecdsa.PublicKey
	priv *ecdsa.PrivateKey
	err  error
}

type confVerifykeysKeyStore struct {
	partners map[string]map[string]confVerifykeysRole
	called   atomic.Bool
}

func (s *confVerifykeysKeyStore) lookup(partner, role string) (confVerifykeysRole, error) {
	s.called.Store(true)
	roles, ok := s.partners[partner]
	if !ok {
		return confVerifykeysRole{}, fmt.Errorf("%w %q", keys.ErrUnknownPartner, partner)
	}
	return roles[role], roles[role].err
}

func (s *confVerifykeysKeyStore) PartnerPublicKeys(_ context.Context, partner string) ([]*ecdsa.PublicKey, error) {
	rv, err := s.lookup(partner, "partnerPublicKeys")
	return rv.pubs, err
}

func (s *confVerifykeysKeyStore) PartnerPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error) {
	pubs, err := s.PartnerPublicKeys(ctx, partner)
	if err != nil {
		return nil, err
	}
	if len(pubs) == 0 {
		return nil, fmt.Errorf("%w: no partner public key", tokens.ErrInvalidPublicKey)
	}
	return pubs[0], nil
}

func (s *confVerifykeysKeyStore) PartnerPrivateKey(_ context.Context, partner string) (*ecdsa.PrivateKey, error) {
	rv, err := s.lookup(partner, "partnerPrivateKey")
	return rv.priv, err
}

func (s *confVerifykeysKeyStore) BoostxPublicKey(_ context.Context, partner string) (*ecdsa.PublicKey, error) {
	rv, err := s.lookup(partner, "boostxPublicKey")
	if err != nil {
		return nil, err
	}
	return rv.pubs[0], nil
}

// confVerifykeysBetStore is the default bet store: setBoost "ok", checkBet true.
type confVerifykeysBetStore struct{ called atomic.Bool }

func (b *confVerifykeysBetStore) SetBoost(context.Context, *tokens.Booster) error {
	b.called.Store(true)
	return nil
}

func (b *confVerifykeysBetStore) CheckBet(context.Context, *tokens.GID) (bool, error) {
	b.called.Store(true)
	return true, nil
}

func (r *confVerifykeysRun) role(v any, partner string, private bool) confVerifykeysRole {
	switch x := v.(type) {
	case nil:
		if private {
			return confVerifykeysRole{err: fmt.Errorf("%w: no partner private key for partner %q", tokens.ErrInvalidPrivateKey, partner)}
		}
		return confVerifykeysRole{err: fmt.Errorf("%w: no public key for partner %q", tokens.ErrInvalidPublicKey, partner)}
	case string:
		if private {
			return confVerifykeysRole{priv: r.privNamed(x)}
		}
		return confVerifykeysRole{pubs: []*ecdsa.PublicKey{r.pubNamed(x)}}
	case []any:
		if !private {
			var pubs []*ecdsa.PublicKey
			for _, n := range x {
				name, _ := n.(string)
				pubs = append(pubs, r.pubNamed(name))
			}
			return confVerifykeysRole{pubs: pubs}
		}
	case map[string]any:
		if len(x) == 1 {
			switch x["error"] {
			case "unknown_partner":
				return confVerifykeysRole{err: fmt.Errorf("%w %q", keys.ErrUnknownPartner, partner)}
			case "other":
				return confVerifykeysRole{err: errors.New("key store unavailable")}
			}
		}
	}
	r.t.Fatalf("key store role value %v is not supported by the VERIFYKEYS runner", v)
	return confVerifykeysRole{}
}

func (r *confVerifykeysRun) keyStore(v any, given bool) *confVerifykeysKeyStore {
	parts := map[string]any{"acme": map[string]any{
		"partnerPublicKeys": []any{"partner"}, "partnerPrivateKey": "partner", "boostxPublicKey": "boostx",
	}}
	if given {
		var ok bool
		if parts, ok = v.(map[string]any); !ok {
			r.t.Fatalf("keyStore %v is not an object", v)
		}
	}
	s := &confVerifykeysKeyStore{partners: map[string]map[string]confVerifykeysRole{}}
	for p, rv := range parts {
		roles, _ := rv.(map[string]any)
		s.partners[p] = map[string]confVerifykeysRole{
			"partnerPublicKeys": r.role(roles["partnerPublicKeys"], p, false),
			"partnerPrivateKey": r.role(roles["partnerPrivateKey"], p, true),
			"boostxPublicKey":   r.role(roles["boostxPublicKey"], p, false),
		}
	}
	return s
}

func (r *confVerifykeysRun) serve(want map[string]any) {
	t, in := r.t, r.c.Input
	r.knownWant(want, "status", "error", "errorPrefix", "allow", "routerMayAnswer", "responseJWT",
		"keyStoreCalled", "betStoreCalled", "at")
	if _, ok := in["betStore"]; ok {
		t.Fatal("the VERIFYKEYS runner supports only the default bet store")
	}
	endpoint, _ := in["endpoint"].(string)
	mount := "/boostx"
	if m, ok := in["mount"].(string); ok {
		mount = m
	}
	var tok *string
	if spec, ok := in["token"]; ok {
		s := r.token(spec, "boostx")
		tok = &s
	}
	req, _ := in["request"].(map[string]any)
	method, path := "POST", strings.TrimSuffix(mount, "/")+"/"+endpoint
	if m, ok := req["method"].(string); ok {
		method = m
	}
	if p, ok := req["path"].(string); ok {
		path = p
	}
	var body []byte
	if h, ok := req["bodyHex"].(string); ok {
		body = r.hexBytes(h)
	} else if b, ok := req["body"].(string); ok {
		body = r.expand(b, tok)
	} else if tok != nil {
		body = r.expand(`{"`+confVerifykeysJWTMember[endpoint]+`":"${token}"}`, tok)
	}
	if n, ok := req["padTo"].(float64); ok {
		at := len(body)
		if a, ok := req["padAt"].(float64); ok {
			if at = int(a); at < 0 {
				at += len(body)
			}
		}
		if int(n) < len(body) || at < 0 || at > len(body) {
			t.Fatalf("padTo %v / padAt %d do not fit a %d-byte body", n, at, len(body))
		}
		body = slices.Concat(body[:at], bytes.Repeat([]byte(" "), int(n)-len(body)), body[at:])
	}

	var ks handlers.KeyStore
	var fake *confVerifykeysKeyStore
	if v, given := in["keyStore"]; !given || v != nil {
		fake = r.keyStore(v, given)
		ks = fake
	}
	bs := &confVerifykeysBetStore{}
	mux := http.NewServeMux()
	panicked := func() (p any) {
		defer func() { p = recover() }()
		handlers.Mount(mux, mount, bs, ks)
		return nil
	}()
	if want["at"] == "construct" {
		if panicked == nil {
			t.Fatal("want a panic from handlers.Mount, got none")
		}
		return
	}
	if panicked != nil {
		t.Fatalf("handlers.Mount panicked: %v", panicked)
	}

	var rb io.Reader = http.NoBody
	if method != http.MethodGet && method != http.MethodHead {
		rb = bytes.NewReader(body)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, rb))

	status, ok := want["status"].(float64)
	if !ok {
		t.Fatal("http.serve want has no status")
	}
	if rec.Code != int(status) {
		t.Errorf("status: want %v, got %d (body %s)", status, rec.Code, rec.Body.Bytes())
	}
	if a, ok := want["allow"]; ok && rec.Header().Get("Allow") != a {
		t.Errorf("allow: want %v, got %q", a, rec.Header().Get("Allow"))
	}
	for name, called := range map[string]bool{
		"keyStoreCalled": fake != nil && fake.called.Load(),
		"betStoreCalled": bs.called.Load(),
	} {
		if w, ok := want[name]; ok && w != called {
			t.Errorf("%s: want %v, got %v", name, w, called)
		}
	}
	// routerMayAnswer: under Mount, ServeMux answers every such request (404, 405)
	// with its own body, so the body is not compared (FORMAT.md 6.7). The standalone
	// handlers' own 405 text is pinned by TestHandlers_MethodNotAllowed.
	if want["routerMayAnswer"] == true {
		return
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if e, ok := want["error"]; ok {
		if msg, isStr := got["error"].(string); len(got) != 1 || !isStr || msg != e {
			t.Errorf(`body: want {"error":%q}, got %s`, e, rec.Body.Bytes())
		}
	}
	if p, ok := want["errorPrefix"].(string); ok {
		if msg, isStr := got["error"].(string); len(got) != 1 || !isStr || !strings.HasPrefix(msg, p) {
			t.Errorf("body: want an error starting %q, got %s", p, rec.Body.Bytes())
		}
	}
	if rj, ok := want["responseJWT"].(map[string]any); ok {
		result, _ := got["result"].(map[string]any)
		jwt, _ := result["responseJWT"].(string)
		keyName, _ := rj["key"].(string)
		partnerID, _ := rj["partnerID"].(string)
		res, err := tokens.ParseVerifyKeysResponseToken(jwt, r.pubNamed(keyName), partnerID, 0)
		if err != nil {
			t.Errorf("responseJWT does not parse: %v (body %s)", err, rec.Body.Bytes())
		} else if float64(res.Nonce) != rj["nonce"] {
			t.Errorf("responseJWT nonce: want %v, got %d", rj["nonce"], res.Nonce)
		}
	}
}
