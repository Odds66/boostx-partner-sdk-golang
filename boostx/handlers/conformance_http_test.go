package handlers_test

// Conformance runner for the HTTP group (testdata/spec/http.json). The
// vector format is described in testdata/spec/FORMAT.md. The runner uses
// the exported API only.

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
	"maps"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/client"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/handlers"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

const confHttpDir = "../../testdata/spec"

type confHttpCase struct {
	Name          string                    `json:"name"`
	Op            string                    `json:"op"`
	Input         map[string]any            `json:"input"`
	Sigs          map[string]map[string]any `json:"sigs"`
	Want          map[string]any            `json:"want"`
	WantZeroValue map[string]any            `json:"wantZeroValue"`
	Needs         []string                  `json:"needs"`
}

// confSkipNeeds skips a case when one of its needs tags names an input Go's
// parameter types cannot express (FORMAT.md section 7). A case tagged only
// ill-formed-string runs: a Go string holds the byte 0xFF.
func confSkipNeeds(t *testing.T, needs []string) bool {
	t.Helper()
	for _, tag := range needs {
		if slices.Contains([]string{"untyped-string", "untyped-number", "fixed-int", "non-finite", "missing-params", "untyped-bool"}, tag) {
			t.Skip("needs " + strings.Join(needs, ","))
			return true
		}
	}
	return false
}

type confHttpSig struct {
	partner, user, bet, sig string
	ids                     bool
}

type confHttpKeys struct {
	priv map[string]*ecdsa.PrivateKey
	pub  map[string]*ecdsa.PublicKey
	sigs map[string]confHttpSig
}

// confHttpTime is a time expression in want: any integer in [v, v+slack].
type confHttpTime struct{ v, slack int64 }

type confHttpRun struct {
	t        *testing.T
	k        *confHttpKeys
	now      int64
	sigs     map[string]confHttpSig
	token    string
	hasToken bool
}

var confHttpCategories = []struct {
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

var confHttpWantKeys = map[string][]string{
	"http.serve": {"status", "allow", "routerMayAnswer", "error", "errorPrefix", "body", "responseJWT",
		"setBoostArg", "checkBetArg", "keyStoreCalled", "betStoreCalled", "at"},
	"client.submit": {"ok", "error", "status", "apiError", "at", "requests", "request", "keyStoreCalled"},
}

func TestConformanceHTTP(t *testing.T) {
	k := confHttpLoadKeys(t)
	var file struct {
		Group string         `json:"group"`
		Cases []confHttpCase `json:"cases"`
	}
	confHttpReadJSON(t, "http.json", &file)
	if len(file.Cases) == 0 {
		t.Fatal("http.json holds no cases")
	}
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if confSkipNeeds(t, c.Needs) {
				return
			}
			r := &confHttpRun{t: t, k: k, now: time.Now().Unix()}
			r.prepareSigs(c.Sigs)
			want := c.Want
			if c.WantZeroValue != nil {
				want = c.WantZeroValue
			}
			allowed, ok := confHttpWantKeys[c.Op]
			if !ok {
				allowed = []string{"ok", "error", "reason"}
			}
			r.allowed("want", want, allowed...)
			want = r.expand(want, true).(map[string]any)
			in := map[string]any{}
			for name, v := range c.Input {
				switch name {
				case "token", "request", "response", "lookups": // expanded where they are used
					in[name] = v
				default:
					in[name] = r.expand(v, false)
				}
			}
			switch c.Op {
			case "http.serve":
				r.serve(in, want)
			case "client.submit":
				r.submit(in, want)
			case "keystore.register":
				r.register(in, want)
			case "booster.parse":
				r.boosterParse(in, want)
			case "checkbet.parse":
				r.checkBetParse(in, want)
			case "verifykeys.parseRequest":
				r.verifyKeysParseRequest(in, want)
			case "verifykeys.createResponse":
				r.verifyKeysCreateResponse(in, want)
			default:
				t.Fatalf("runner does not support op %q", c.Op)
			}
		})
	}
}

// --- loading ------------------------------------------------------------------------------------------------------

func confHttpReadJSON(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(confHttpDir, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func confHttpLoadKeys(t *testing.T) *confHttpKeys {
	var tk struct {
		Keys          map[string]map[string]string `json:"keys"`
		GIDSignatures []struct {
			Key, Partner, User, Bet, Signature string
		} `json:"gidSignatures"`
	}
	confHttpReadJSON(t, "testkeys.json", &tk)
	k := &confHttpKeys{priv: map[string]*ecdsa.PrivateKey{}, pub: map[string]*ecdsa.PublicKey{}, sigs: map[string]confHttpSig{}}
	der := func(text string) []byte {
		b, _ := pem.Decode([]byte(text))
		if b == nil {
			t.Fatal("testkeys.json: bad PEM")
		}
		return b.Bytes
	}
	for name, forms := range tk.Keys {
		if name == "p384" {
			priv, err := x509.ParsePKCS8PrivateKey(der(forms["pkcs8"]))
			if err != nil {
				t.Fatal(err)
			}
			pub, err := x509.ParsePKIXPublicKey(der(forms["spki"]))
			if err != nil {
				t.Fatal(err)
			}
			k.priv["@unusable"], k.pub["@unusable"] = priv.(*ecdsa.PrivateKey), pub.(*ecdsa.PublicKey)
			continue
		}
		priv, err := keys.LoadPrivateKeyFromPEM([]byte(forms["pkcs8"]))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		pub, err := keys.LoadPublicKeyFromPEM([]byte(forms["spki"]))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		k.priv[name], k.pub[name] = priv, pub
	}
	for _, s := range tk.GIDSignatures {
		name := map[string]string{"partner": "gid", "partner2": "gid2"}[s.Key]
		if name == "" {
			t.Fatalf("testkeys.json: unexpected gid signature key %q", s.Key)
		}
		k.sigs[name] = confHttpSig{partner: s.Partner, user: s.User, bet: s.Bet, sig: s.Signature, ids: true}
	}
	return k
}

func (r *confHttpRun) prepareSigs(sigs map[string]map[string]any) {
	r.sigs = maps.Clone(r.k.sigs)
	for name, s := range sigs {
		switch {
		case s["fixed"] != nil:
			r.sigs[name] = confHttpSig{sig: s["fixed"].(string)}
		case s["text"] != nil:
			r.sigs[name] = confHttpSig{sig: confHttpSign(r.privKey(s["key"]), r.text(s["text"].(string)))}
		default:
			p, u, b := s["partner"].(string), s["user"].(string), s["bet"].(string)
			g, err := tokens.BuildGID(p, u, b, r.privKey(s["key"]))
			if err != nil {
				r.t.Fatalf("sigs.%s: BuildGID: %v", name, err)
			}
			r.sigs[name] = confHttpSig{partner: p, user: u, bet: b, sig: g.Signature, ids: true}
		}
	}
}

func (r *confHttpRun) allowed(what string, m map[string]any, names ...string) {
	r.t.Helper()
	for name := range m {
		if !slices.Contains(names, name) {
			r.t.Fatalf("runner does not support %s member %q", what, name)
		}
	}
}

// --- key references -----------------------------------------------------------------------------------------------

func (r *confHttpRun) privKey(ref any) *ecdsa.PrivateKey {
	if ref == nil {
		return nil
	}
	k, ok := r.k.priv[ref.(string)]
	if !ok {
		r.t.Fatalf("unknown key %v", ref)
	}
	return k
}

func (r *confHttpRun) pubKey(ref any) *ecdsa.PublicKey {
	if ref == nil {
		return nil
	}
	k, ok := r.k.pub[ref.(string)]
	if !ok {
		r.t.Fatalf("unknown key %v", ref)
	}
	return k
}

func (r *confHttpRun) pubList(ref any) []*ecdsa.PublicKey {
	list := ref.([]any)
	out := make([]*ecdsa.PublicKey, 0, len(list))
	for _, x := range list {
		out = append(out, r.pubKey(x))
	}
	return out
}

// --- placeholders -------------------------------------------------------------------------------------------------

var (
	confHttpPlaceholder = regexp.MustCompile(`\$\{([^}]*)\}`)
	confHttpWhole       = regexp.MustCompile(`^\$\{([^}]*)\}$`)
	confHttpTimeExpr    = regexp.MustCompile(`^now(Ms)?(?:([+-])(\d+))?$`)
)

// resolve returns a confHttpTime, a string, or (in text fields) raw bytes.
func (r *confHttpRun) resolve(expr string, inText bool) any {
	if m := confHttpTimeExpr.FindStringSubmatch(expr); m != nil {
		base, slack := r.now, int64(5)
		if m[1] != "" {
			base, slack = r.now*1000, 5000
		}
		var n int64
		if m[2] != "" {
			fmt.Sscan(m[3], &n)
			if m[2] == "-" {
				n = -n
			}
		}
		return confHttpTime{base + n, slack}
	}
	if name, ok := strings.CutPrefix(expr, "sig:"); ok {
		s, ok := r.sigs[name]
		if !ok {
			r.t.Fatalf("unknown signature %q", name)
		}
		return s.sig
	}
	if expr == "gid" || strings.HasPrefix(expr, "gid:") {
		name := strings.TrimPrefix(strings.TrimPrefix(expr, "gid"), ":")
		if name == "" {
			name = "gid"
		}
		s, ok := r.sigs[name]
		if !ok || !s.ids {
			r.t.Fatalf("${%s} needs a signature with ids", expr)
		}
		b, _ := json.Marshal(struct {
			Partner   string `json:"partner"`
			User      string `json:"user"`
			Bet       string `json:"bet"`
			Signature string `json:"signature"`
		}{s.partner, s.user, s.bet, s.sig})
		return string(b)
	}
	if h, ok := strings.CutPrefix(expr, "hex:"); ok && inText {
		b, err := hex.DecodeString(h)
		if err != nil {
			r.t.Fatalf("bad ${%s}", expr)
		}
		return b
	}
	if expr == "token" && inText {
		if !r.hasToken {
			r.t.Fatal("${token} without a token")
		}
		return confHttpEscape(r.token)
	}
	if expr == "$" {
		return "$"
	}
	r.t.Fatalf("bad placeholder ${%s}", expr)
	return nil
}

// text expands a text field to bytes.
func (r *confHttpRun) text(s string) []byte {
	var out []byte
	last := 0
	for _, m := range confHttpPlaceholder.FindAllStringSubmatchIndex(s, -1) {
		out = append(out, s[last:m[0]]...)
		switch v := r.resolve(s[m[2]:m[3]], true).(type) {
		case confHttpTime:
			out = fmt.Appendf(out, "%d", v.v)
		case string:
			out = append(out, v...)
		case []byte:
			out = append(out, v...)
		}
		last = m[1]
	}
	return append(out, s[last:]...)
}

// expand replaces whole-string placeholders and special values in a JSON value.
func (r *confHttpRun) expand(v any, forWant bool) any {
	switch v := v.(type) {
	case string:
		m := confHttpWhole.FindStringSubmatch(v)
		if m == nil {
			return v
		}
		res := r.resolve(m[1], false)
		if tm, ok := res.(confHttpTime); ok {
			if forWant {
				return tm
			}
			return float64(tm.v)
		}
		return res
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = r.expand(x, forWant)
		}
		return out
	case map[string]any:
		if n, ok := v["$number"]; ok {
			return map[string]float64{"NaN": math.NaN(), "Infinity": math.Inf(1), "-Infinity": math.Inf(-1), "-0": math.Copysign(0, -1)}[n.(string)]
		}
		if s, ok := v["$illFormed"]; ok {
			return s.(string) + "\xff"
		}
		out := make(map[string]any, len(v))
		for name, x := range v {
			out[name] = r.expand(x, forWant)
		}
		return out
	}
	return v
}

// confHttpEscape JSON-string-escapes s without quotes: '"', '\' and C0 controls only.
func confHttpEscape(s string) string {
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

// --- tokens -------------------------------------------------------------------------------------------------------

const confHttpAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func confHttpB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func confHttpSign(k *ecdsa.PrivateKey, data []byte) string {
	h := sha256.Sum256(data)
	rr, ss, err := ecdsa.Sign(rand.Reader, k, h[:])
	if err != nil {
		panic(err)
	}
	n := (k.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*n)
	rr.FillBytes(sig[:n])
	ss.FillBytes(sig[n:])
	return confHttpB64(sig)
}

func confHttpTransform(text string, tr any) (string, error) {
	switch v := tr.(type) {
	case string:
		switch v {
		case "pad":
			if len(text)%4 == 0 {
				return text + "====", nil
			}
			return text + strings.Repeat("=", 4-len(text)%4), nil
		case "std-alphabet":
			return strings.NewReplacer("-", "+", "_", "/").Replace(text), nil
		case "trailing-bits":
			i := -1
			if len(text)%4 != 0 {
				i = strings.IndexByte(confHttpAlphabet, text[len(text)-1])
			}
			if i < 0 || i+1 >= len(confHttpAlphabet) {
				return "", fmt.Errorf("trailing-bits does not apply to %q", text)
			}
			return text[:len(text)-1] + confHttpAlphabet[i+1:i+2], nil
		case "empty":
			return "", nil
		case "zero":
			return confHttpB64(make([]byte, 64)), nil
		case "flip":
			b, err := base64.RawURLEncoding.DecodeString(text)
			if err != nil || len(b) == 0 {
				return "", fmt.Errorf("flip does not apply to %q", text)
			}
			b[0] ^= 1
			return confHttpB64(b), nil
		}
	case map[string]any:
		if ins, ok := v["insert"].(string); ok {
			at := int(v["at"].(float64))
			if at < 0 {
				at += len(text)
			}
			return text[:at] + ins + text[at:], nil
		}
		if s, ok := v["append"].(string); ok {
			return text + s, nil
		}
		if n, ok := v["truncate"].(float64); ok {
			return text[:len(text)-int(n)], nil
		}
		if n, ok := v["segments"].(float64); ok {
			parts := strings.Split(text, ".")
			return strings.Join(parts[:min(int(n), len(parts))], "."), nil
		}
	}
	return "", fmt.Errorf("unsupported transform %v", tr)
}

func confHttpApply(text string, list any) (string, error) {
	l, _ := list.([]any)
	for _, tr := range l {
		out, err := confHttpTransform(text, tr)
		if err != nil {
			return "", err
		}
		if out == text {
			return "", fmt.Errorf("transform %v left the text unchanged", tr)
		}
		text = out
	}
	return text, nil
}

// buildToken builds a token spec (FORMAT 6.8); defKey is the operation's default signing key.
func (r *confHttpRun) buildToken(specV any, defKey string) string {
	spec := specV.(map[string]any)
	r.allowed("token", spec, "raw", "header", "headerHex", "payload", "payloadHex", "headerSegment",
		"payloadSegment", "key", "signature", "transform")
	if raw, ok := spec["raw"].(string); ok {
		return string(r.text(raw))
	}
	seg := func(name, def string) []byte {
		if h, ok := spec[name+"Hex"].(string); ok {
			b, err := hex.DecodeString(h)
			if err != nil {
				r.t.Fatalf("bad %sHex", name)
			}
			return b
		}
		if s, ok := spec[name].(string); ok {
			return r.text(s)
		}
		if def == "" {
			r.t.Fatalf("token spec without %s", name)
		}
		return []byte(def)
	}
	h, err := confHttpApply(confHttpB64(seg("header", `{"alg":"ES256","typ":"JWT"}`)), spec["headerSegment"])
	if err != nil {
		r.t.Fatalf("headerSegment: %v", err)
	}
	p, err := confHttpApply(confHttpB64(seg("payload", "")), spec["payloadSegment"])
	if err != nil {
		r.t.Fatalf("payloadSegment: %v", err)
	}
	keyRef := any(defKey)
	if k, ok := spec["key"]; ok {
		keyRef = k
	}
	priv := r.privKey(keyRef)
	sigList, _ := spec["signature"].([]any)
	for i := 0; ; i++ {
		s, err := confHttpApply(confHttpSign(priv, []byte(h+"."+p)), spec["signature"])
		if err != nil {
			if i < 63 && slices.Contains(sigList, any("std-alphabet")) {
				continue
			}
			r.t.Fatalf("signature: %v", err)
		}
		tok, err := confHttpApply(h+"."+p+"."+s, spec["transform"])
		if err != nil {
			r.t.Fatalf("transform: %v", err)
		}
		return tok
	}
}

// checkBuilt applies the implicit builder checks of FORMAT 5.3 and compares payload and absent.
func (r *confHttpRun) checkBuilt(tok string, pub *ecdsa.PublicKey, w map[string]any) error {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return fmt.Errorf("token has %d segments", len(parts))
	}
	dec := make([][]byte, 3)
	for i, s := range parts {
		b, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil || confHttpB64(b) != s {
			return fmt.Errorf("segment %d is not canonical base64url", i)
		}
		dec[i] = b
	}
	var header any
	if err := json.Unmarshal(dec[0], &header); err != nil {
		return fmt.Errorf("header: %v", err)
	}
	if err := confHttpMatch(header, map[string]any{"alg": "ES256", "typ": "JWT"}, "header", true); err != nil {
		return err
	}
	n := len(dec[2]) / 2
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(dec[2]) != 64 || !ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(dec[2][:n]), new(big.Int).SetBytes(dec[2][n:])) {
		return errors.New("JWS signature does not verify")
	}
	var payload map[string]any
	if err := json.Unmarshal(dec[1], &payload); err != nil {
		return fmt.Errorf("payload: %v", err)
	}
	for root, v := range payload {
		m, _ := v.(map[string]any)
		if g, ok := m["gid"].(map[string]any); ok {
			str := func(k string) string { s, _ := g[k].(string); return s }
			gid := &tokens.GID{Partner: str("partner"), User: str("user"), Bet: str("bet"), Signature: str("signature")}
			if err := tokens.VerifyGID(gid, pub); err != nil {
				return fmt.Errorf("%s.gid does not verify: %v", root, err)
			}
		}
	}
	if p, ok := w["payload"]; ok {
		if err := confHttpMatch(payload, p, "payload", false); err != nil {
			return err
		}
	}
	absent, _ := w["absent"].([]any)
	for _, a := range absent {
		path := strings.Split(a.(string), ".")
		var o any = payload
		for _, part := range path[:len(path)-1] {
			m, _ := o.(map[string]any)
			o = m[part]
		}
		if m, ok := o.(map[string]any); ok {
			if _, present := m[path[len(path)-1]]; present {
				return fmt.Errorf("%s is present", a)
			}
		}
	}
	return nil
}

// --- comparison ---------------------------------------------------------------------------------------------------

// confHttpMatch compares got with want (FORMAT 5.3); exact also requires the same object members at every level.
func confHttpMatch(got, want any, path string, exact bool) error {
	switch w := want.(type) {
	case confHttpTime:
		g, ok := got.(float64)
		if !ok || g != math.Trunc(g) || g < float64(w.v) || g > float64(w.v+w.slack) {
			return fmt.Errorf("%s: got %#v (%.0f), want %d..%d", path, got, g, w.v, w.v+w.slack)
		}
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return fmt.Errorf("%s: got %#v, want %d elements", path, got, len(w))
		}
		for i := range w {
			if err := confHttpMatch(g[i], w[i], fmt.Sprintf("%s[%d]", path, i), exact); err != nil {
				return err
			}
		}
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: got %#v, want an object", path, got)
		}
		if exact && len(g) != len(w) {
			return fmt.Errorf("%s: got members %v, want %v", path, slices.Sorted(maps.Keys(g)), slices.Sorted(maps.Keys(w)))
		}
		for name, wv := range w {
			gv, present := g[name]
			if !present {
				return fmt.Errorf("%s.%s: missing", path, name)
			}
			if err := confHttpMatch(gv, wv, path+"."+name, exact); err != nil {
				return err
			}
		}
	case float64:
		if g, ok := got.(float64); !ok || g != w {
			return fmt.Errorf("%s: got %#v, want %v", path, got, w)
		}
	default:
		if got != want {
			return fmt.Errorf("%s: got %#v, want %#v", path, got, want)
		}
	}
	return nil
}

func confHttpErrorSet(err error) []string {
	var out []string
	for _, c := range confHttpCategories {
		if errors.Is(err, c.err) {
			out = append(out, c.name)
		}
	}
	var ae *client.APIError
	if errors.As(err, &ae) {
		out = append(out, "api_error")
	}
	sort.Strings(out)
	return out
}

// outcome checks err against want's ok or error; checkOK compares an accepted result.
func (r *confHttpRun) outcome(err error, want map[string]any, checkOK func(ok map[string]any) error) error {
	if okw, ok := want["ok"]; ok {
		if err != nil {
			return fmt.Errorf("want ok, got error %v (%v)", confHttpErrorSet(err), err)
		}
		if checkOK != nil {
			return checkOK(okw.(map[string]any))
		}
		return nil
	}
	wl, ok := want["error"].([]any)
	if !ok {
		r.t.Fatal("want has neither ok nor an error list")
	}
	if err == nil {
		return fmt.Errorf("want error %v, got success", wl)
	}
	var ws []string
	for _, x := range wl {
		ws = append(ws, x.(string))
	}
	sort.Strings(ws)
	if got := confHttpErrorSet(err); !slices.Equal(got, ws) {
		return fmt.Errorf("error set: got %v, want %v (%v)", got, ws, err)
	}
	if reason, ok := want["reason"]; ok && tokens.VerifyKeysReason(err) != reason {
		return fmt.Errorf("reason: got %q, want %q (%v)", tokens.VerifyKeysReason(err), reason, err)
	}
	var ae *client.APIError
	errors.As(err, &ae)
	if st, ok := want["status"].(float64); ok && (ae == nil || ae.StatusCode != int(st)) {
		return fmt.Errorf("status: want %v, got %v", st, err)
	}
	if msg, ok := want["apiError"]; ok && (ae == nil || ae.Message != msg) {
		return fmt.Errorf("apiError: want %q, got %v", msg, err)
	}
	return nil
}

func (r *confHttpRun) report(err error) {
	r.t.Helper()
	if err != nil {
		r.t.Error(err)
	}
}

func confHttpGIDMap(g *tokens.GID) any {
	if g == nil {
		return nil
	}
	return map[string]any{"partner": g.Partner, "user": g.User, "bet": g.Bet, "signature": g.Signature}
}

func confHttpBoosterMap(b *tokens.Booster) any {
	if b == nil {
		return nil
	}
	return map[string]any{"gid": confHttpGIDMap(&b.GID), "round": float64(b.Round), "boost": b.Boost,
		"final": b.Final, "jackpot": b.Jackpot, "iat": float64(b.IssuedAt)}
}

func confHttpPanics(f func()) (p any) {
	defer func() { p = recover() }()
	f()
	return nil
}

// --- fakes --------------------------------------------------------------------------------------------------------

func confHttpWait(ctx context.Context, ms any) error {
	d, _ := ms.(float64)
	if d <= 0 {
		return nil
	}
	select {
	case <-time.After(time.Duration(d * float64(time.Millisecond))):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// confHttpStore is a key store over role values (FORMAT 6.7): entries maps a partner to its roles, or, for the
// client store, straight to the private-key role value.
type confHttpStore struct {
	r       *confHttpRun
	entries map[string]any
	client  bool
	called  atomic.Bool
}

func (s *confHttpStore) lookup(ctx context.Context, partner, role string) (any, error) {
	s.called.Store(true)
	e, ok := s.entries[partner]
	if !ok {
		return nil, fmt.Errorf("%w %q", keys.ErrUnknownPartner, partner)
	}
	v := e
	if !s.client {
		m, _ := e.(map[string]any)
		v = m[role]
	}
	if m, ok := v.(map[string]any); ok {
		switch m["error"] {
		case "unknown_partner":
			return nil, fmt.Errorf("%w %q", keys.ErrUnknownPartner, partner)
		case "other":
			return nil, errors.New("conformance: key store failure")
		}
		if err := confHttpWait(ctx, m["delayMs"]); err != nil {
			return nil, err
		}
		v = m["key"]
	}
	if v == nil {
		if role == "partnerPrivateKey" {
			return nil, fmt.Errorf("%w: role not given", tokens.ErrInvalidPrivateKey)
		}
		return nil, fmt.Errorf("%w: role not given", tokens.ErrInvalidPublicKey)
	}
	return v, nil
}

func (s *confHttpStore) PartnerPublicKeys(ctx context.Context, partner string) ([]*ecdsa.PublicKey, error) {
	v, err := s.lookup(ctx, partner, "partnerPublicKeys")
	if err != nil {
		return nil, err
	}
	if _, ok := v.([]any); !ok {
		v = []any{v}
	}
	return s.r.pubList(v), nil
}

func (s *confHttpStore) PartnerPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error) {
	ks, err := s.PartnerPublicKeys(ctx, partner)
	if err != nil {
		return nil, err
	}
	if len(ks) == 0 {
		return nil, fmt.Errorf("%w: empty key list", tokens.ErrInvalidPublicKey)
	}
	return ks[0], nil
}

func (s *confHttpStore) PartnerPrivateKey(ctx context.Context, partner string) (*ecdsa.PrivateKey, error) {
	v, err := s.lookup(ctx, partner, "partnerPrivateKey")
	if err != nil {
		return nil, err
	}
	return s.r.privKey(v), nil
}

func (s *confHttpStore) BoostxPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error) {
	v, err := s.lookup(ctx, partner, "boostxPublicKey")
	if err != nil {
		return nil, err
	}
	return s.r.pubKey(v), nil
}

type confHttpBets struct {
	mode   string
	called atomic.Bool
	boost  *tokens.Booster
}

func (b *confHttpBets) SetBoost(_ context.Context, x *tokens.Booster) error {
	b.called.Store(true)
	b.boost = x
	switch b.mode {
	case "reject":
		return handlers.ErrRoundRejected
	case "reject-wrapped":
		return fmt.Errorf("x: %w", handlers.ErrRoundRejected)
	case "error":
		return errors.New("conformance: bet store failure")
	}
	return nil
}

type confHttpChecker struct {
	*confHttpBets
	verdict any
	gid     *tokens.GID
}

func (c *confHttpChecker) CheckBet(_ context.Context, g *tokens.GID) (bool, error) {
	c.called.Store(true)
	c.gid = g
	if c.verdict == "error" {
		return false, errors.New("conformance: bet store failure")
	}
	return c.verdict.(bool), nil
}

type confHttpSent struct {
	url, method, contentType string
	body                     []byte
}

// confHttpTransport serves the case's canned response and records every request.
type confHttpTransport struct {
	resp     map[string]any
	body     []byte
	mu       sync.Mutex
	sent     []confHttpSent
	followed bool
}

func (rt *confHttpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var b []byte
	if req.Body != nil {
		b, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}
	rt.mu.Lock()
	rt.sent = append(rt.sent, confHttpSent{req.URL.String(), req.Method, req.Header.Get("Content-Type"), b})
	if req.Response != nil { // the client is following a redirect
		rt.followed = true
	}
	rt.mu.Unlock()
	if rt.resp["networkError"] == true {
		return nil, errors.New("conformance: connection refused")
	}
	if err := confHttpWait(req.Context(), rt.resp["delayMs"]); err != nil {
		return nil, err
	}
	status := 200
	if s, ok := rt.resp["status"].(float64); ok {
		status = int(s)
	}
	h := http.Header{}
	headers, ok := rt.resp["headers"].(map[string]any)
	if !ok {
		headers = map[string]any{"content-type": "application/json"}
	}
	for name, v := range headers {
		h.Set(name, v.(string))
	}
	return &http.Response{
		Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), StatusCode: status,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: h, Request: req, ContentLength: -1,
		Body: &confHttpBody{ctx: req.Context(), delay: rt.resp["bodyDelayMs"], r: bytes.NewReader(rt.body)},
	}, nil
}

type confHttpBody struct {
	ctx    context.Context
	delay  any
	waited bool
	r      *bytes.Reader
}

func (b *confHttpBody) Read(p []byte) (int, error) {
	if !b.waited {
		b.waited = true
		if err := confHttpWait(b.ctx, b.delay); err != nil {
			return 0, err
		}
	}
	return b.r.Read(p)
}

func (b *confHttpBody) Close() error { return nil }

// bodyBytes expands a request or response body spec, with padTo/padAt.
func (r *confHttpRun) bodyBytes(spec map[string]any, def string) []byte {
	var b []byte
	if h, ok := spec["bodyHex"].(string); ok {
		var err error
		if b, err = hex.DecodeString(h); err != nil {
			r.t.Fatal("bad bodyHex")
		}
	} else if s, ok := spec["body"].(string); ok {
		b = r.text(s)
	} else {
		b = r.text(def)
	}
	if to, ok := spec["padTo"].(float64); ok && int(to) > len(b) {
		at := len(b)
		if a, ok := spec["padAt"].(float64); ok {
			at = int(a)
			if at < 0 {
				at += len(b)
			}
		}
		b = slices.Insert(b, at, bytes.Repeat([]byte{' '}, int(to)-len(b))...)
	}
	return b
}

// --- operations ---------------------------------------------------------------------------------------------------

var confHttpTokenField = map[string]string{"set-boost": "boosterJWT", "check-bet": "checkbetJWT", "verify-keys": "verifyKeysJWT"}

func (r *confHttpRun) serve(in, want map[string]any) {
	t := r.t
	r.allowed("input", in, "mount", "endpoint", "token", "request", "keyStore", "betStore")
	endpoint := in["endpoint"].(string)
	if spec, ok := in["token"]; ok {
		r.token, r.hasToken = r.buildToken(spec, "boostx"), true
	}
	mount := "/boostx"
	if m, ok := in["mount"]; ok {
		mount = m.(string)
	}

	store := &confHttpStore{r: r, entries: map[string]any{"acme": map[string]any{
		"partnerPublicKeys": []any{"partner"}, "partnerPrivateKey": "partner", "boostxPublicKey": "boostx"}}}
	var ks handlers.KeyStore = store
	if v, ok := in["keyStore"]; ok {
		if v == nil {
			ks = nil
		} else {
			store.entries = v.(map[string]any)
		}
	}

	bsSpec := map[string]any{"setBoost": "ok", "checkBet": true}
	if v, ok := in["betStore"].(map[string]any); ok {
		maps.Copy(bsSpec, v)
	}
	bets := &confHttpBets{mode: bsSpec["setBoost"].(string)}
	if !slices.Contains([]string{"ok", "reject", "reject-wrapped", "error"}, bets.mode) {
		t.Fatalf("unsupported setBoost %q", bets.mode)
	}
	var bs handlers.BetStoreUpdater = bets
	var checker *confHttpChecker
	switch v := bsSpec["checkBet"]; v {
	case "absent":
	case true, false, "error":
		checker = &confHttpChecker{confHttpBets: bets, verdict: v}
		bs = checker
	default:
		t.Fatalf("unrepresentable input in an untagged case: checkBet verdict %#v cannot be returned by a Go BetStoreChecker, whose verdict is a bool", v)
	}

	mux := http.NewServeMux()
	p := confHttpPanics(func() { handlers.Mount(mux, mount, bs, ks) })
	if want["at"] == "construct" {
		if p == nil {
			t.Error("want a panic from handlers.Mount, got none")
		}
		return
	}
	if p != nil {
		t.Fatalf("handlers.Mount panicked: %v", p)
	}

	req, _ := in["request"].(map[string]any)
	r.allowed("request", req, "method", "path", "body", "bodyHex", "padTo", "padAt")
	method, path := "POST", strings.TrimSuffix(mount, "/")+"/"+endpoint
	if m, ok := req["method"].(string); ok {
		method = m
	}
	if p, ok := req["path"].(string); ok {
		path = p
	}
	def := ""
	if r.hasToken {
		def = `{"` + confHttpTokenField[endpoint] + `":"${token}"}`
	}
	var body io.Reader
	if method != http.MethodGet && method != http.MethodHead {
		body = bytes.NewReader(r.bodyBytes(req, def))
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, body))

	if st := int(want["status"].(float64)); rec.Code != st {
		t.Errorf("status: got %d, want %d (body %q)", rec.Code, st, rec.Body.String())
	}
	if a, ok := want["allow"]; ok && rec.Header().Get("Allow") != a {
		t.Errorf("Allow: got %q, want %q", rec.Header().Get("Allow"), a)
	}
	// routerMayAnswer: under Mount, ServeMux answers every such request (404, 405)
	// with its own body, so the body is not compared (FORMAT.md 6.7). The standalone
	// handlers' own 405 text is pinned by TestHandlers_MethodNotAllowed.
	if want["routerMayAnswer"] != true {
		var got any
		jsonErr := json.Unmarshal(rec.Body.Bytes(), &got)
		needJSON := func() bool {
			if jsonErr != nil {
				t.Errorf("body is not JSON: %q", rec.Body.String())
			}
			return jsonErr == nil
		}
		if e, ok := want["error"]; ok && needJSON() {
			r.report(confHttpMatch(got, map[string]any{"error": e}, "body", true))
		}
		if pre, ok := want["errorPrefix"].(string); ok && needJSON() {
			m, _ := got.(map[string]any)
			s, isString := m["error"].(string)
			if len(m) != 1 || !isString || !strings.HasPrefix(s, pre) {
				t.Errorf("body: got %q, want {\"error\": %q...}", rec.Body.String(), pre)
			}
		}
		if w, ok := want["body"]; ok && needJSON() {
			r.report(confHttpMatch(got, w, "body", true))
		}
		if w, ok := want["responseJWT"].(map[string]any); ok && needJSON() {
			m, _ := got.(map[string]any)
			res, _ := m["result"].(map[string]any)
			tok, _ := res["responseJWT"].(string)
			resp, err := tokens.ParseVerifyKeysResponseToken(tok, r.pubKey(w["key"]), w["partnerID"].(string), 0)
			if err != nil {
				t.Errorf("responseJWT: %v (body %q)", err, rec.Body.String())
			} else {
				r.report(confHttpMatch(float64(resp.Nonce), w["nonce"], "responseJWT.nonce", false))
			}
		}
	}
	if w, ok := want["setBoostArg"]; ok {
		r.report(confHttpMatch(confHttpBoosterMap(bets.boost), w, "setBoostArg", false))
	}
	if w, ok := want["checkBetArg"]; ok {
		var g *tokens.GID
		if checker != nil {
			g = checker.gid
		}
		r.report(confHttpMatch(confHttpGIDMap(g), w, "checkBetArg", false))
	}
	if w, ok := want["keyStoreCalled"]; ok && store.called.Load() != w {
		t.Errorf("keyStoreCalled: got %v, want %v", store.called.Load(), w)
	}
	if w, ok := want["betStoreCalled"]; ok && bets.called.Load() != w {
		t.Errorf("betStoreCalled: got %v, want %v", bets.called.Load(), w)
	}
}

// settlementParams converts neutral settlement parameters, failing on values Go's types cannot hold.
func (r *confHttpRun) settlementParams(v any) tokens.SettlementParams {
	m, ok := v.(map[string]any)
	if !ok {
		r.t.Fatal("unrepresentable input in an untagged case: params null or absent: SettlementParams is a struct")
	}
	r.allowed("params", m, "partner", "user", "bet", "status", "amount", "currency", "version", "xSettle", "settledAt")
	str := func(name string) string {
		x, present := m[name]
		s, ok := x.(string)
		if present && x != nil && !ok {
			r.t.Fatalf("unrepresentable input in an untagged case: %s %#v is not a string", name, x)
		}
		return s
	}
	i64 := func(name string) int64 {
		x := m[name]
		if x == nil {
			return 0
		}
		f, ok := x.(float64)
		if !ok || f != math.Trunc(f) || math.Abs(f) > 1<<63-1 {
			r.t.Fatalf("unrepresentable input in an untagged case: %s %#v is not an int64", name, x)
		}
		return int64(f)
	}
	p := tokens.SettlementParams{Partner: str("partner"), User: str("user"), Bet: str("bet"), Status: str("status"),
		Currency: str("currency"), Version: i64("version"), SettledAt: i64("settledAt")}
	if a, ok := m["amount"].(float64); ok {
		p.Amount = a
	}
	if x, ok := m["xSettle"].(float64); ok {
		p.XSettle = &x
	}
	return p
}

func (r *confHttpRun) submit(in, want map[string]any) {
	t := r.t
	r.allowed("input", in, "keyStore", "options", "params", "cancel", "response")
	store := &confHttpStore{r: r, entries: map[string]any{"acme": "partner"}, client: true}
	var ks client.KeyStore = store
	if v, ok := in["keyStore"]; ok {
		if v == nil {
			ks = nil
		} else {
			store.entries = v.(map[string]any)
		}
	}
	resp, _ := in["response"].(map[string]any)
	r.allowed("response", resp, "status", "headers", "body", "bodyHex", "padTo", "padAt", "delayMs", "bodyDelayMs", "networkError")
	rt := &confHttpTransport{resp: resp, body: r.bodyBytes(resp, "")}
	hc := &http.Client{Transport: rt}
	base := any("https://boostx.test")
	if opts, ok := in["options"].(map[string]any); ok {
		r.allowed("options", opts, "baseURL", "timeoutMs")
		if b, ok := opts["baseURL"]; ok {
			base = b
		}
		if ms, ok := opts["timeoutMs"].(float64); ok {
			hc.Timeout = time.Duration(ms * float64(time.Millisecond))
		}
	}
	var opts []client.Option
	if base != nil {
		opts = append(opts, client.WithBaseURL(base.(string)))
	}
	opts = append(opts, client.WithHTTPClient(hc))
	params := r.settlementParams(in["params"])

	var cl *client.Client
	p := confHttpPanics(func() { cl = client.New(ks, opts...) })
	if want["at"] == "construct" {
		if p == nil {
			t.Error("want a panic from client.New, got none")
		}
		return
	}
	if p != nil {
		t.Fatalf("client.New panicked: %v", p)
	}
	ctx := context.Background()
	if c, ok := in["cancel"]; ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		if c == "before" {
			cancel()
		} else {
			time.AfterFunc(time.Duration(c.(map[string]any)["afterMs"].(float64)*float64(time.Millisecond)), cancel)
		}
	}
	err := cl.SubmitSettlement(ctx, params)
	r.report(r.outcome(err, want, nil))

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.followed {
		t.Error("the client followed a redirect")
	}
	if n, ok := want["requests"].(float64); ok && len(rt.sent) != int(n) {
		t.Errorf("requests: got %d, want %v", len(rt.sent), n)
	}
	if w, ok := want["request"].(map[string]any); ok {
		if len(rt.sent) != 1 {
			t.Fatalf("request: %d requests sent", len(rt.sent))
		}
		s := rt.sent[0]
		r.report(confHttpMatch(s.url, w["url"], "request.url", false))
		r.report(confHttpMatch(s.method, w["method"], "request.method", false))
		r.report(confHttpMatch(s.contentType, w["contentType"], "request.contentType", false))
		var body map[string]any
		if err := json.Unmarshal(s.body, &body); err != nil {
			t.Fatalf("request body: %v", err)
		}
		tok, ok := body["settlementJWT"].(string)
		if len(body) != 1 || !ok {
			t.Fatalf("request body: %s", s.body)
		}
		r.report(r.checkBuilt(tok, r.pubKey(store.entries[params.Partner]), w))
	}
	if w, ok := want["keyStoreCalled"]; ok && store.called.Load() != w {
		t.Errorf("keyStoreCalled: got %v, want %v", store.called.Load(), w)
	}
}

func (r *confHttpRun) register(in, want map[string]any) {
	r.allowed("input", in, "partner", "partnerPublicKey", "partnerPrivateKey", "boostxPublicKey", "lookups")
	partner, ok := in["partner"].(string)
	if !ok {
		r.t.Fatalf("unrepresentable input in an untagged case: partner %#v is not a string", in["partner"])
	}
	s := keys.NewMemoryKeyStore()
	priv, bpub := r.privKey(in["partnerPrivateKey"]), r.pubKey(in["boostxPublicKey"])
	var err error
	if list, ok := in["partnerPublicKey"].([]any); ok {
		err = s.RegisterWithPartnerPublicKeys(partner, r.pubList(list), priv, bpub)
	} else {
		err = s.Register(partner, r.pubKey(in["partnerPublicKey"]), priv, bpub)
	}
	r.report(r.outcome(err, want, nil))

	lookups, _ := in["lookups"].([]any)
	for i, lv := range lookups {
		l := lv.(map[string]any)
		method, p := l["method"].(string), l["partner"].(string)
		lw := r.expand(l["want"], true).(map[string]any)
		ctx := context.Background()
		var err error
		var check func(ok map[string]any) error
		switch method {
		case "partnerPublicKeys":
			var got []*ecdsa.PublicKey
			got, err = s.PartnerPublicKeys(ctx, p)
			check = func(ok map[string]any) error {
				want := r.pubList(ok["keys"])
				if !slices.EqualFunc(got, want, func(a, b *ecdsa.PublicKey) bool { return a.Equal(b) }) {
					return fmt.Errorf("got %d keys, not %v", len(got), ok["keys"])
				}
				return nil
			}
		case "partnerPrivateKey":
			var got *ecdsa.PrivateKey
			got, err = s.PartnerPrivateKey(ctx, p)
			check = func(ok map[string]any) error {
				if !got.Equal(r.privKey(ok["key"])) {
					return fmt.Errorf("got another key than %v", ok["key"])
				}
				return nil
			}
		case "boostxPublicKey":
			var got *ecdsa.PublicKey
			got, err = s.BoostxPublicKey(ctx, p)
			check = func(ok map[string]any) error {
				if !got.Equal(r.pubKey(ok["key"])) {
					return fmt.Errorf("got another key than %v", ok["key"])
				}
				return nil
			}
		default:
			r.t.Fatalf("unsupported lookup method %q", method)
		}
		if e := r.outcome(err, lw, check); e != nil {
			r.t.Errorf("lookup %d (%s %q): %v", i, method, p, e)
		}
	}
}

func (r *confHttpRun) inboundKeys(in map[string]any) (*ecdsa.PublicKey, []*ecdsa.PublicKey) {
	r.allowed("input", in, "token", "boostxKey", "partnerKeys")
	bk := r.pubKey("boostx")
	if v, ok := in["boostxKey"]; ok {
		bk = r.pubKey(v)
	}
	pks := []*ecdsa.PublicKey{r.pubKey("partner")}
	if v, ok := in["partnerKeys"]; ok {
		pks = r.pubList(v)
	}
	return bk, pks
}

func (r *confHttpRun) boosterParse(in, want map[string]any) {
	bk, pks := r.inboundKeys(in)
	b, err := tokens.ParseBoosterTokenWithKeys(r.buildToken(in["token"], "boostx"), bk, pks)
	r.report(r.outcome(err, want, func(ok map[string]any) error {
		return confHttpMatch(confHttpBoosterMap(b), ok, "ok", false)
	}))
}

func (r *confHttpRun) checkBetParse(in, want map[string]any) {
	bk, pks := r.inboundKeys(in)
	cb, err := tokens.ParseCheckBetTokenWithKeys(r.buildToken(in["token"], "boostx"), bk, pks)
	r.report(r.outcome(err, want, func(ok map[string]any) error {
		return confHttpMatch(map[string]any{"gid": confHttpGIDMap(&cb.GID), "iat": float64(cb.IssuedAt)}, ok, "ok", false)
	}))
}

func (r *confHttpRun) verifyKeysParseRequest(in, want map[string]any) {
	r.allowed("input", in, "token", "key", "partnerID", "windowSeconds")
	key := r.pubKey("boostx")
	if v, ok := in["key"]; ok {
		key = r.pubKey(v)
	}
	partnerID := "acme"
	if v, ok := in["partnerID"]; ok {
		partnerID = v.(string)
	}
	var window time.Duration
	if v, ok := in["windowSeconds"]; ok && v != nil {
		w := v.(float64)
		if math.IsNaN(w) || math.IsInf(w, 0) {
			r.t.Fatalf("unrepresentable input in an untagged case: windowSeconds %v is not a time.Duration", w)
		}
		window = time.Duration(w * 1e9)
	}
	vr, err := tokens.ParseVerifyKeysRequestToken(r.buildToken(in["token"], "boostx"), key, partnerID, window)
	r.report(r.outcome(err, want, func(ok map[string]any) error {
		return confHttpMatch(map[string]any{"partnerID": vr.PartnerID, "nonce": float64(vr.Nonce), "iat": float64(vr.IssuedAt)}, ok, "ok", false)
	}))
}

func (r *confHttpRun) verifyKeysCreateResponse(in, want map[string]any) {
	r.allowed("input", in, "key", "partnerID", "nonce")
	keyRef := any("partner")
	if v, ok := in["key"]; ok {
		keyRef = v
	}
	partnerID, _ := in["partnerID"].(string)
	n, _ := in["nonce"].(float64)
	if n != math.Trunc(n) || n < math.MinInt32 || n > math.MaxInt32 {
		r.t.Fatalf("unrepresentable input in an untagged case: nonce %v is not an int32", n)
	}
	tok, err := tokens.CreateVerifyKeysResponseToken(r.privKey(keyRef), partnerID, int32(n))
	r.report(r.outcome(err, want, func(ok map[string]any) error {
		return r.checkBuilt(tok, r.pubKey(keyRef), ok)
	}))
}
