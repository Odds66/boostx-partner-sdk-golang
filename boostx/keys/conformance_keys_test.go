package keys_test

// Conformance runner for the KEYS group (testdata/spec/keys.json), as
// testdata/spec/FORMAT.md defines the format. It uses the exported API
// only. Inputs and expectations the runner does not implement fail the case
// rather than pass silently.

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
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"sort"
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

const confKeysDir = "../../testdata/spec/"

type confKeysCase struct {
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

type confKeysPair struct {
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
}

// confKeysSig is a named GID signature; ids is set when partner, user and bet
// are known, which ${gid:NAME} needs.
type confKeysSig struct {
	partner, user, bet, sig string
	ids                     bool
}

type confKeysEnv struct {
	pems  map[string]map[string]string
	pairs map[string]confKeysPair // the test keys, plus "@unusable"
	fixed map[string]confKeysSig  // "gid" and "gid2"
}

func TestConformanceKeys(t *testing.T) {
	env := confKeysLoadEnv(t)
	var file struct {
		Cases []confKeysCase `json:"cases"`
	}
	confKeysReadJSON(t, "keys.json", &file)
	for _, cs := range file.Cases {
		t.Run(cs.Name, func(t *testing.T) { confKeysRunCase(t, env, cs) })
	}
}

func confKeysReadJSON(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(confKeysDir + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func confKeysLoadEnv(t *testing.T) *confKeysEnv {
	var tk struct {
		Keys          map[string]map[string]string `json:"keys"`
		GIDSignatures []struct {
			Key, Partner, User, Bet, Signature string
		} `json:"gidSignatures"`
	}
	confKeysReadJSON(t, "testkeys.json", &tk)
	env := &confKeysEnv{pems: tk.Keys, pairs: map[string]confKeysPair{}, fixed: map[string]confKeysSig{}}
	for name, k := range tk.Keys {
		if name == "p384" {
			continue
		}
		priv, err := keys.LoadPrivateKeyFromPEM([]byte(k["pkcs8"]))
		if err != nil {
			t.Fatalf("key %s: %v", name, err)
		}
		pub, err := keys.LoadPublicKeyFromPEM([]byte(k["spki"]))
		if err != nil {
			t.Fatalf("key %s: %v", name, err)
		}
		env.pairs[name] = confKeysPair{priv, pub}
	}
	// "@unusable" is the P-384 pair, loaded with the platform's own crypto.
	privBlock, _ := pem.Decode([]byte(tk.Keys["p384"]["pkcs8"]))
	pubBlock, _ := pem.Decode([]byte(tk.Keys["p384"]["spki"]))
	if privBlock == nil || pubBlock == nil {
		t.Fatal("p384: no PEM block")
	}
	priv, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	env.pairs["@unusable"] = confKeysPair{priv.(*ecdsa.PrivateKey), pub.(*ecdsa.PublicKey)}
	names := map[string]string{"partner": "gid", "partner2": "gid2"}
	for _, s := range tk.GIDSignatures {
		env.fixed[names[s.Key]] = confKeysSig{s.Partner, s.User, s.Bet, s.Signature, true}
	}
	return env
}

func (e *confKeysEnv) pair(ref any) (confKeysPair, error) {
	name, ok := ref.(string)
	p, found := e.pairs[name]
	if !ok || !found {
		return confKeysPair{}, fmt.Errorf("unknown key reference %v", ref)
	}
	return p, nil
}

func (e *confKeysEnv) pub(ref any) (*ecdsa.PublicKey, error) {
	if ref == nil {
		return nil, nil
	}
	p, err := e.pair(ref)
	return p.pub, err
}

func (e *confKeysEnv) priv(ref any) (*ecdsa.PrivateKey, error) {
	if ref == nil {
		return nil, nil
	}
	p, err := e.pair(ref)
	return p.priv, err
}

func (e *confKeysEnv) pubs(ref any) ([]*ecdsa.PublicKey, error) {
	if ref == nil {
		return nil, nil
	}
	list, ok := ref.([]any)
	if !ok {
		return nil, fmt.Errorf("key list expected, got %v", ref)
	}
	out := make([]*ecdsa.PublicKey, len(list))
	for i, r := range list {
		k, err := e.pub(r)
		if err != nil {
			return nil, err
		}
		out[i] = k
	}
	return out, nil
}

// confKeysCtx is one case's state: the clock read once, the named signatures
// and the built token.
type confKeysCtx struct {
	t     *testing.T
	env   *confKeysEnv
	now   int64
	sigs  map[string]confKeysSig
	token string
}

func (c *confKeysCtx) must(err error) {
	c.t.Helper()
	if err != nil {
		c.t.Fatalf("broken vector: %v", err)
	}
}

func (c *confKeysCtx) pub(ref any) *ecdsa.PublicKey {
	k, err := c.env.pub(ref)
	c.must(err)
	return k
}

func (c *confKeysCtx) priv(ref any) *ecdsa.PrivateKey {
	k, err := c.env.priv(ref)
	c.must(err)
	return k
}

func (c *confKeysCtx) pubs(ref any) []*ecdsa.PublicKey {
	k, err := c.env.pubs(ref)
	c.must(err)
	return k
}

// only fails the case on a member the runner does not implement.
func (c *confKeysCtx) only(where string, m map[string]any, allowed ...string) {
	c.t.Helper()
	for k := range m {
		if !slices.Contains(allowed, k) {
			c.t.Fatalf("%s: member %q is not implemented by this runner", where, k)
		}
	}
}

// --- placeholders (FORMAT.md 3) ---

var (
	confKeysPlaceholder = regexp.MustCompile(`\$\{([^}]*)\}`)
	confKeysTimeExpr    = regexp.MustCompile(`^now(Ms)?(?:([+-])(\d+))?$`)
)

// confKeysTime is a time expression; in want it matches [at, at+slack].
type confKeysTime struct{ at, slack float64 }

func (c *confKeysCtx) resolve(expr string, inText bool) any {
	if m := confKeysTimeExpr.FindStringSubmatch(expr); m != nil {
		base, slack := c.now, 5.0
		if m[1] != "" {
			base, slack = c.now*1000, 5000
		}
		if m[2] != "" {
			n, err := strconv.ParseInt(m[3], 10, 64)
			c.must(err)
			if m[2] == "-" {
				n = -n
			}
			base += n
		}
		return confKeysTime{float64(base), slack}
	}
	switch {
	case strings.HasPrefix(expr, "sig:"):
		return c.sig(expr[4:]).sig
	case expr == "gid" || strings.HasPrefix(expr, "gid:"):
		name := strings.TrimPrefix(strings.TrimPrefix(expr, "gid"), ":")
		if name == "" {
			name = "gid"
		}
		s := c.sig(name)
		if !s.ids {
			c.t.Fatalf("broken vector: ${gid:%s} needs the ids form", name)
		}
		b, err := json.Marshal(struct {
			Partner   string `json:"partner"`
			User      string `json:"user"`
			Bet       string `json:"bet"`
			Signature string `json:"signature"`
		}{s.partner, s.user, s.bet, s.sig})
		c.must(err)
		return string(b)
	case strings.HasPrefix(expr, "hex:") && inText:
		b, err := hex.DecodeString(expr[4:])
		c.must(err)
		return b
	case expr == "token" && inText:
		return confKeysEscape(c.token)
	case expr == "$":
		return "$"
	}
	c.t.Fatalf("broken vector: placeholder ${%s}", expr)
	return nil
}

func (c *confKeysCtx) sig(name string) confKeysSig {
	s, ok := c.sigs[name]
	if !ok {
		c.t.Fatalf("broken vector: no signature %q", name)
	}
	return s
}

// confKeysEscape escapes ", \ and C0 controls, nothing else (FORMAT.md 3, ${token}).
func confKeysEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch ch := s[i]; {
		case ch == '"' || ch == '\\':
			b.WriteByte('\\')
			b.WriteByte(ch)
		case ch < 0x20:
			fmt.Fprintf(&b, `\u%04x`, ch)
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}

// text expands a text field to bytes.
func (c *confKeysCtx) text(s string) []byte {
	var out []byte
	last := 0
	for _, m := range confKeysPlaceholder.FindAllStringSubmatchIndex(s, -1) {
		out = append(out, s[last:m[0]]...)
		switch v := c.resolve(s[m[2]:m[3]], true).(type) {
		case confKeysTime:
			out = strconv.AppendInt(out, int64(v.at), 10)
		case []byte:
			out = append(out, v...)
		case string:
			out = append(out, v...)
		}
		last = m[1]
	}
	return append(out, s[last:]...)
}

// expand expands a JSON value: whole-string placeholders and special values.
func (c *confKeysCtx) expand(v any, forWant bool) any {
	switch x := v.(type) {
	case string:
		m := confKeysPlaceholder.FindStringSubmatchIndex(x)
		if m == nil || m[0] != 0 || m[1] != len(x) {
			return x
		}
		r := c.resolve(x[m[2]:m[3]], false)
		if tm, ok := r.(confKeysTime); ok && !forWant {
			return tm.at
		}
		return r
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = c.expand(e, forWant)
		}
		return out
	case map[string]any:
		if n, ok := x["$number"]; ok && len(x) == 1 {
			special := map[any]float64{"NaN": math.NaN(), "Infinity": math.Inf(1), "-Infinity": math.Inf(-1), "-0": math.Copysign(0, -1)}
			f, ok := special[n]
			if !ok {
				c.t.Fatalf("broken vector: $number %v", n)
			}
			return f
		}
		if s, ok := x["$illFormed"].(string); ok && len(x) == 1 {
			return s + "\xff"
		}
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = c.expand(e, forWant)
		}
		return out
	}
	return v
}

func (c *confKeysCtx) prepareSigs(sigs map[string]map[string]any) {
	c.sigs = maps.Clone(c.env.fixed)
	for name, s := range sigs {
		switch {
		case s["fixed"] != nil:
			c.sigs[name] = confKeysSig{sig: s["fixed"].(string)}
		case s["text"] != nil:
			c.sigs[name] = confKeysSig{sig: confKeysSign(c.priv(s["key"]), c.text(s["text"].(string)))}
		default:
			p, u, b := s["partner"].(string), s["user"].(string), s["bet"].(string)
			g, err := tokens.BuildGID(p, u, b, c.priv(s["key"]))
			c.must(err)
			c.sigs[name] = confKeysSig{p, u, b, g.Signature, true}
		}
	}
}

// --- tokens (FORMAT.md 6.8) ---

const confKeysAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func confKeysB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// confKeysSign is ES256 over data as base64url of r || s.
func confKeysSign(priv *ecdsa.PrivateKey, data []byte) string {
	h := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		panic(err)
	}
	n := (priv.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*n)
	r.FillBytes(sig[:n])
	s.FillBytes(sig[n:])
	return confKeysB64(sig)
}

// confKeysVerify checks a base64url r || s ES256 signature over data.
func confKeysVerify(pub *ecdsa.PublicKey, data []byte, sigText string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(sigText)
	if err != nil || len(sig) != 64 {
		return false
	}
	h := sha256.Sum256(data)
	return ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

func confKeysTransform(text string, tr any) (string, error) {
	switch tr {
	case "pad":
		return text + strings.Repeat("=", 4-len(text)%4), nil
	case "std-alphabet":
		return strings.NewReplacer("-", "+", "_", "/").Replace(text), nil
	case "trailing-bits":
		i := -1
		if text != "" {
			i = strings.IndexByte(confKeysAlphabet, text[len(text)-1])
		}
		if len(text)%4 == 0 || i < 0 || i == 63 {
			return "", fmt.Errorf("trailing-bits does not apply to %q", text)
		}
		return text[:len(text)-1] + confKeysAlphabet[i+1:i+2], nil
	case "empty":
		return "", nil
	case "zero":
		return confKeysB64(make([]byte, 64)), nil
	case "flip":
		b, err := base64.RawURLEncoding.DecodeString(text)
		if err != nil || len(b) == 0 {
			return "", fmt.Errorf("flip does not apply to %q", text)
		}
		b[0] ^= 1
		return confKeysB64(b), nil
	}
	m, _ := tr.(map[string]any)
	num := func(k string) int {
		f, _ := m[k].(float64)
		return int(f)
	}
	switch {
	case m["insert"] != nil:
		at := num("at")
		if at < 0 {
			at += len(text)
		}
		return text[:at] + m["insert"].(string) + text[at:], nil
	case m["append"] != nil:
		return text + m["append"].(string), nil
	case m["truncate"] != nil:
		return text[:len(text)-num("truncate")], nil
	case m["segments"] != nil:
		parts := strings.Split(text, ".")
		return strings.Join(parts[:min(num("segments"), len(parts))], "."), nil
	}
	return "", fmt.Errorf("unknown transform %v", tr)
}

func confKeysApply(text string, list any, what string) (string, error) {
	ts, _ := list.([]any)
	for _, tr := range ts {
		out, err := confKeysTransform(text, tr)
		if err != nil {
			return "", fmt.Errorf("%s: %w", what, err)
		}
		if out == text {
			return "", fmt.Errorf("%s: transform %v left it unchanged", what, tr)
		}
		text = out
	}
	return text, nil
}

func (c *confKeysCtx) buildToken(v any, defKey string) string {
	spec, ok := v.(map[string]any)
	if !ok {
		c.t.Fatalf("broken vector: token spec %v", v)
	}
	c.only("token", spec, "raw", "header", "headerHex", "payload", "payloadHex", "headerSegment", "payloadSegment", "key", "signature", "transform")
	if raw, ok := spec["raw"].(string); ok {
		return string(c.text(raw))
	}
	seg := func(hexKey, textKey string, def *string) string {
		if h, ok := spec[hexKey].(string); ok {
			b, err := hex.DecodeString(h)
			c.must(err)
			return confKeysB64(b)
		}
		s, ok := spec[textKey].(string)
		if !ok {
			if def == nil {
				c.t.Fatalf("broken vector: token spec without %s", textKey)
			}
			s = *def
		}
		return confKeysB64(c.text(s))
	}
	defHeader := `{"alg":"ES256","typ":"JWT"}`
	h, err := confKeysApply(seg("headerHex", "header", &defHeader), spec["headerSegment"], "header")
	c.must(err)
	p, err := confKeysApply(seg("payloadHex", "payload", nil), spec["payloadSegment"], "payload")
	c.must(err)
	keyRef := any(defKey)
	if k, ok := spec["key"]; ok {
		keyRef = k
	}
	priv := c.priv(keyRef)
	sigTransforms, _ := spec["signature"].([]any)
	for i := 0; ; i++ {
		s, err := confKeysApply(confKeysSign(priv, []byte(h+"."+p)), sigTransforms, "signature")
		if err != nil && i < 63 && slices.Contains(sigTransforms, any("std-alphabet")) {
			continue // a signature without - or _: sign again
		}
		c.must(err)
		tok, err := confKeysApply(h+"."+p+"."+s, spec["transform"], "token")
		c.must(err)
		return tok
	}
}

// --- inputs ---

// def returns in[k], or d when the member is left out.
func confKeysDef(in map[string]any, k string, d any) any {
	if v, ok := in[k]; ok {
		return v
	}
	return d
}

// str reads a string input; null is the zero value, anything else unrepresentable.
func (c *confKeysCtx) str(v any) string {
	switch s := v.(type) {
	case nil:
		return ""
	case string:
		return s
	}
	c.t.Fatalf("unrepresentable input in an untagged case: a string parameter cannot hold %v", v)
	return ""
}

func (c *confKeysCtx) num(v any) float64 {
	switch f := v.(type) {
	case nil:
		return 0
	case float64:
		return f
	}
	c.t.Fatalf("unrepresentable input in an untagged case: a float64 parameter cannot hold %v", v)
	return 0
}

// integer reads an integer input in [lo, hi]; anything else is unrepresentable.
func (c *confKeysCtx) integer(v any, lo, hi float64) int64 {
	f := c.num(v)
	if f != math.Trunc(f) || f < lo || f > hi {
		c.t.Fatalf("unrepresentable input in an untagged case: an integer parameter cannot hold %v", v)
	}
	return int64(f)
}

func (c *confKeysCtx) boolean(v any) bool {
	switch b := v.(type) {
	case nil:
		return false
	case bool:
		return b
	}
	c.t.Fatalf("unrepresentable input in an untagged case: a bool parameter cannot hold %v", v)
	return false
}

func (c *confKeysCtx) params(in map[string]any) map[string]any {
	v, ok := in["params"]
	if ok && v == nil {
		c.t.Fatal("unrepresentable input in an untagged case: a params struct cannot be missing")
	}
	m, _ := v.(map[string]any)
	return m
}

const confKeysMaxSafe = 1<<53 - 1

func (c *confKeysCtx) gamePassParams(m map[string]any) tokens.GamePassParams {
	var p tokens.GamePassParams
	for k, v := range m {
		switch k {
		case "partner":
			p.Partner = c.str(v)
		case "user":
			p.User = c.str(v)
		case "bet":
			p.Bet = c.str(v)
		case "amount":
			p.Amount = c.num(v)
		case "currency":
			p.Currency = c.str(v)
		case "x":
			p.X = c.num(v)
		case "xMin":
			p.XMin = c.num(v)
		case "xMax":
			p.XMax = c.num(v)
		case "xDecimals":
			p.XDecimals = int(c.integer(v, -confKeysMaxSafe, confKeysMaxSafe))
		case "eventTitle":
			p.EventTitle = c.str(v)
		case "demo":
			p.Demo = c.boolean(v)
		default:
			c.t.Fatalf("broken vector: gamepass parameter %q", k)
		}
	}
	return p
}

func (c *confKeysCtx) settlementParams(m map[string]any) tokens.SettlementParams {
	var p tokens.SettlementParams
	for k, v := range m {
		switch k {
		case "partner":
			p.Partner = c.str(v)
		case "user":
			p.User = c.str(v)
		case "bet":
			p.Bet = c.str(v)
		case "status":
			p.Status = c.str(v)
		case "amount":
			p.Amount = c.num(v)
		case "currency":
			p.Currency = c.str(v)
		case "version":
			p.Version = c.integer(v, -confKeysMaxSafe, confKeysMaxSafe)
		case "xSettle":
			if v != nil {
				x := c.num(v)
				p.XSettle = &x
			}
		case "settledAt":
			p.SettledAt = c.integer(v, -confKeysMaxSafe, confKeysMaxSafe)
		default:
			c.t.Fatalf("broken vector: settlement parameter %q", k)
		}
	}
	return p
}

func (c *confKeysCtx) pemInput(in map[string]any) []byte {
	if h, ok := in["pemHex"].(string); ok {
		b, err := hex.DecodeString(h)
		c.must(err)
		return b
	}
	var text string
	if v, ok := in["pem"]; ok {
		switch p := v.(type) {
		case nil:
			return nil
		case string:
			text = p
		default:
			c.t.Fatalf("unrepresentable input in an untagged case: the loader takes bytes and cannot be given %v", v)
		}
	} else {
		name, form, _ := strings.Cut(c.str(in["pemRef"]), ".")
		var found bool
		text, found = c.env.pems[name][form]
		if !found {
			c.t.Fatalf("broken vector: pemRef %v", in["pemRef"])
		}
	}
	list, _ := in["replace"].([]any)
	for _, r := range list {
		pair := r.([]any)
		text = strings.ReplaceAll(text, pair[0].(string), pair[1].(string))
	}
	return []byte(text)
}

// body builds a request or response body: body, bodyHex or def, then padTo/padAt.
func (c *confKeysCtx) body(spec map[string]any, def string) []byte {
	var b []byte
	switch {
	case spec["bodyHex"] != nil:
		var err error
		b, err = hex.DecodeString(spec["bodyHex"].(string))
		c.must(err)
	case spec["body"] != nil:
		b = c.text(spec["body"].(string))
	default:
		b = c.text(def)
	}
	if padTo, ok := spec["padTo"].(float64); ok && int(padTo) > len(b) {
		at := len(b)
		if a, ok := spec["padAt"].(float64); ok {
			at = int(a)
			if at < 0 {
				at += len(b)
			}
		}
		pad := bytes.Repeat([]byte(" "), int(padTo)-len(b))
		b = append(b[:at:at], append(pad, b[at:]...)...)
	}
	return b
}

// --- fakes ---

// confKeysStore is the fake key store of http.serve and client.submit, over
// the role values of FORMAT.md 6.6 and 6.7: roles maps a partner to its role
// value (flat, the client store) or to {role: value} (the handler store).
type confKeysStore struct {
	env    *confKeysEnv
	roles  map[string]any
	flat   bool
	called atomic.Bool
}

func (s *confKeysStore) value(ctx context.Context, partner, role string) (any, error) {
	s.called.Store(true)
	entry, listed := s.roles[partner]
	if !listed {
		return nil, fmt.Errorf("%w %q", keys.ErrUnknownPartner, partner)
	}
	v := entry
	if !s.flat {
		m, _ := entry.(map[string]any)
		v = m[role]
	}
	if m, ok := v.(map[string]any); ok {
		switch m["error"] {
		case "unknown_partner":
			return nil, fmt.Errorf("%w %q", keys.ErrUnknownPartner, partner)
		case "other":
			return nil, errors.New("key store failure")
		case nil:
		default:
			return nil, fmt.Errorf("broken vector: role error %v", m["error"])
		}
		ms, _ := m["delayMs"].(float64)
		select {
		case <-time.After(time.Duration(ms * float64(time.Millisecond))):
		case <-ctx.Done():
			return nil, ctx.Err()
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

func (s *confKeysStore) PartnerPublicKeys(ctx context.Context, partner string) ([]*ecdsa.PublicKey, error) {
	v, err := s.value(ctx, partner, "partnerPublicKeys")
	if err != nil {
		return nil, err
	}
	if _, ok := v.([]any); !ok {
		v = []any{v}
	}
	return s.env.pubs(v)
}

func (s *confKeysStore) PartnerPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error) {
	list, err := s.PartnerPublicKeys(ctx, partner)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%w: no partner public key", tokens.ErrInvalidPublicKey)
	}
	return list[0], nil
}

func (s *confKeysStore) PartnerPrivateKey(ctx context.Context, partner string) (*ecdsa.PrivateKey, error) {
	v, err := s.value(ctx, partner, "partnerPrivateKey")
	if err != nil {
		return nil, err
	}
	return s.env.priv(v)
}

func (s *confKeysStore) BoostxPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error) {
	v, err := s.value(ctx, partner, "boostxPublicKey")
	if err != nil {
		return nil, err
	}
	return s.env.pub(v)
}

// confKeysBets is the fake bet store of http.serve; confKeysCheckingBets adds CheckBet.
type confKeysBets struct {
	setBoost, checkBet any
	called             atomic.Bool
}

func (b *confKeysBets) SetBoost(context.Context, *tokens.Booster) error {
	b.called.Store(true)
	switch b.setBoost {
	case "ok":
		return nil
	case "reject":
		return handlers.ErrRoundRejected
	case "reject-wrapped":
		return fmt.Errorf("x: %w", handlers.ErrRoundRejected)
	}
	return errors.New("bet store failure")
}

type confKeysCheckingBets struct{ *confKeysBets }

func (b confKeysCheckingBets) CheckBet(context.Context, *tokens.GID) (bool, error) {
	b.called.Store(true)
	if v, ok := b.checkBet.(bool); ok {
		return v, nil
	}
	return false, errors.New("bet store failure")
}

// confKeysTransport is the fake transport of client.submit.
type confKeysTransport struct {
	resp     map[string]any
	body     []byte
	requests atomic.Int32
	followed atomic.Bool
}

func (f *confKeysTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.requests.Add(1)
	if req.Response != nil {
		f.followed.Store(true) // the client followed a redirect
	}
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	if f.resp["networkError"] == true {
		return nil, errors.New("network unreachable")
	}
	status := 200
	if s, ok := f.resp["status"].(float64); ok {
		status = int(s)
	}
	h := http.Header{"Content-Type": {"application/json"}}
	if hs, ok := f.resp["headers"].(map[string]any); ok {
		h = http.Header{}
		for k, v := range hs {
			h.Set(k, fmt.Sprint(v))
		}
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(f.body)), Request: req}, nil
}

// confKeysRec records what a case observed besides its result.
type confKeysRec struct {
	panicked   bool
	panicValue any
	ks         *confKeysStore
	bs         *confKeysBets
	tr         *confKeysTransport
}

// construct runs f, recording a panic as an error at construction.
func (r *confKeysRec) construct(f func()) {
	defer func() {
		if v := recover(); v != nil {
			r.panicked, r.panicValue = true, v
		}
	}()
	f()
}

// --- operations (FORMAT.md 6) ---

func confKeysGID(g tokens.GID) map[string]any {
	return map[string]any{"partner": g.Partner, "user": g.User, "bet": g.Bet, "signature": g.Signature}
}

func (c *confKeysCtx) run(op string, in map[string]any, rec *confKeysRec) (any, error) {
	switch op {
	case "key.loadPrivate", "key.loadPublic":
		c.only("input", in, "pem", "pemRef", "pemHex", "replace")
		if op == "key.loadPrivate" {
			return keys.LoadPrivateKeyFromPEM(c.pemInput(in))
		}
		return keys.LoadPublicKeyFromPEM(c.pemInput(in))

	case "keystore.register":
		c.only("input", in, "partner", "partnerPublicKey", "partnerPrivateKey", "boostxPublicKey", "lookups")
		ks := keys.NewMemoryKeyStore()
		partner := c.str(in["partner"])
		priv, bx := c.priv(in["partnerPrivateKey"]), c.pub(in["boostxPublicKey"])
		var err error
		if list, ok := in["partnerPublicKey"].([]any); ok {
			err = ks.RegisterWithPartnerPublicKeys(partner, c.pubs(list), priv, bx)
		} else {
			err = ks.Register(partner, c.pub(in["partnerPublicKey"]), priv, bx)
		}
		lookups, _ := in["lookups"].([]any)
		for i, l := range lookups {
			if lerr := c.lookup(ks, l.(map[string]any)); lerr != nil {
				c.t.Errorf("lookup %d: %v", i, lerr)
			}
		}
		return map[string]any{}, err

	case "gid.build":
		c.only("input", in, "key", "partner", "user", "bet")
		g, err := tokens.BuildGID(c.str(in["partner"]), c.str(in["user"]), c.str(in["bet"]), c.priv(confKeysDef(in, "key", "partner")))
		if err != nil {
			return nil, err
		}
		return map[string]any{"gid": confKeysGID(*g)}, nil

	case "gamepass.create":
		c.only("input", in, "key", "params")
		return tokens.CreateGamePassToken(c.priv(confKeysDef(in, "key", "partner")), c.gamePassParams(c.params(in)))

	case "settlement.create":
		c.only("input", in, "key", "params")
		return tokens.CreateSettlementToken(c.priv(confKeysDef(in, "key", "partner")), c.settlementParams(c.params(in)))

	case "verifykeys.createRequest", "verifykeys.createResponse":
		c.only("input", in, "key", "partnerID", "nonce")
		nonce := int32(c.integer(in["nonce"], math.MinInt32, math.MaxInt32))
		if op == "verifykeys.createRequest" {
			return tokens.CreateVerifyKeysRequestToken(c.priv(confKeysDef(in, "key", "boostx")), c.str(in["partnerID"]), nonce)
		}
		return tokens.CreateVerifyKeysResponseToken(c.priv(confKeysDef(in, "key", "partner")), c.str(in["partnerID"]), nonce)

	case "booster.extract", "checkbet.extract", "verifykeys.extractRequest":
		c.only("input", in, "token")
		extract := map[string]func(string) (string, error){
			"booster.extract":           tokens.ExtractBoosterPartner,
			"checkbet.extract":          tokens.ExtractCheckBetPartner,
			"verifykeys.extractRequest": tokens.ExtractVerifyKeysRequestPartner,
		}[op]
		p, err := extract(c.buildToken(in["token"], "boostx"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"partner": p}, nil

	case "booster.parse", "checkbet.parse":
		c.only("input", in, "token", "boostxKey", "partnerKeys")
		tok := c.buildToken(in["token"], "boostx")
		bx := c.pub(confKeysDef(in, "boostxKey", "boostx"))
		pks := c.pubs(confKeysDef(in, "partnerKeys", []any{"partner"}))
		if op == "checkbet.parse" {
			cb, err := tokens.ParseCheckBetTokenWithKeys(tok, bx, pks)
			if err != nil {
				return nil, err
			}
			return map[string]any{"gid": confKeysGID(cb.GID), "iat": float64(cb.IssuedAt)}, nil
		}
		b, err := tokens.ParseBoosterTokenWithKeys(tok, bx, pks)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"gid": confKeysGID(b.GID), "round": float64(b.Round), "boost": b.Boost,
			"final": b.Final, "jackpot": b.Jackpot, "iat": float64(b.IssuedAt),
		}, nil

	case "verifykeys.parseRequest", "verifykeys.parseResponse":
		c.only("input", in, "token", "key", "partnerID", "windowSeconds")
		def := "boostx"
		if op == "verifykeys.parseResponse" {
			def = "partner"
		}
		tok := c.buildToken(in["token"], def)
		key := c.pub(confKeysDef(in, "key", def))
		partnerID := c.str(confKeysDef(in, "partnerID", "acme"))
		w := c.num(in["windowSeconds"])
		if math.IsNaN(w) {
			c.t.Fatal("unrepresentable input in an untagged case: a time.Duration cannot hold NaN")
		}
		window := time.Duration(w * 1e9)
		if op == "verifykeys.parseRequest" {
			r, err := tokens.ParseVerifyKeysRequestToken(tok, key, partnerID, window)
			if err != nil {
				return nil, err
			}
			return map[string]any{"partnerID": r.PartnerID, "nonce": float64(r.Nonce), "iat": float64(r.IssuedAt)}, nil
		}
		r, err := tokens.ParseVerifyKeysResponseToken(tok, key, partnerID, window)
		if err != nil {
			return nil, err
		}
		return map[string]any{"partnerID": r.PartnerID, "nonce": float64(r.Nonce), "iat": float64(r.IssuedAt)}, nil

	case "client.submit":
		return c.submit(in, rec)

	case "http.serve":
		return c.serve(in, rec), nil
	}
	c.t.Fatalf("operation %q is not implemented by this runner", op)
	return nil, nil
}

// lookup runs one keystore.register lookup and checks it against its want.
func (c *confKeysCtx) lookup(ks *keys.MemoryKeyStore, l map[string]any) error {
	ctx, p := context.Background(), c.str(l["partner"])
	var got []any
	var err error
	role := "pub"
	switch l["method"] {
	case "partnerPublicKeys":
		var list []*ecdsa.PublicKey
		list, err = ks.PartnerPublicKeys(ctx, p)
		for _, k := range list {
			got = append(got, k)
		}
	case "partnerPrivateKey":
		role = "priv"
		var k *ecdsa.PrivateKey
		k, err = ks.PartnerPrivateKey(ctx, p)
		got = []any{k}
	case "boostxPublicKey":
		var k *ecdsa.PublicKey
		k, err = ks.BoostxPublicKey(ctx, p)
		got = []any{k}
	default:
		c.t.Fatalf("broken vector: lookup method %v", l["method"])
	}
	w, _ := l["want"].(map[string]any)
	ok, isOK := w["ok"].(map[string]any)
	if !isOK {
		if err == nil {
			return fmt.Errorf("%v(%q): want error %v, got a key", l["method"], p, w["error"])
		}
		return confKeysCheckErr(err, w)
	}
	if err != nil {
		return fmt.Errorf("%v(%q): want a key, got %v", l["method"], p, err)
	}
	names, _ := ok["keys"].([]any)
	if k, has := ok["key"]; has {
		names = []any{k}
	}
	if len(got) != len(names) {
		return fmt.Errorf("%v(%q): got %d keys, want %d", l["method"], p, len(got), len(names))
	}
	for i, n := range names {
		pair, perr := c.env.pair(n)
		c.must(perr)
		want := any(pair.pub)
		if role == "priv" {
			want = pair.priv
		}
		if got[i] != want {
			return fmt.Errorf("%v(%q): key %d is not %v", l["method"], p, i, n)
		}
	}
	return nil
}

func (c *confKeysCtx) submit(in map[string]any, rec *confKeysRec) (any, error) {
	c.only("input", in, "keyStore", "options", "params", "cancel", "response")
	roles := confKeysDef(in, "keyStore", map[string]any{"acme": "partner"})
	opts, _ := in["options"].(map[string]any)
	c.only("options", opts, "baseURL", "timeoutMs")
	resp, _ := in["response"].(map[string]any)
	c.only("response", resp, "status", "headers", "body", "bodyHex", "padTo", "padAt", "networkError")
	params := c.settlementParams(c.params(in))

	rec.tr = &confKeysTransport{resp: resp, body: c.body(resp, "")}
	hc := &http.Client{Transport: rec.tr}
	if ms, ok := opts["timeoutMs"].(float64); ok {
		hc.Timeout = time.Duration(ms * float64(time.Millisecond))
	}
	options := []client.Option{client.WithHTTPClient(hc)}
	if base := confKeysDef(opts, "baseURL", "https://boostx.test"); base != nil {
		options = append(options, client.WithBaseURL(c.str(base)))
	}
	var store client.KeyStore
	if roles != nil {
		rec.ks = &confKeysStore{env: c.env, roles: roles.(map[string]any), flat: true}
		store = rec.ks
	}
	var cl *client.Client
	rec.construct(func() { cl = client.New(store, options...) })
	if rec.panicked {
		return nil, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	switch cv := in["cancel"].(type) {
	case nil:
	case string:
		if cv != "before" {
			c.t.Fatalf("broken vector: cancel %q", cv)
		}
		cancel()
	case map[string]any:
		ms, _ := cv["afterMs"].(float64)
		time.AfterFunc(time.Duration(ms*float64(time.Millisecond)), cancel)
	}
	err := cl.SubmitSettlement(ctx, params)
	if rec.tr.followed.Load() {
		c.t.Errorf("the client followed a redirect")
	}
	return map[string]any{}, err
}

func (c *confKeysCtx) serve(in map[string]any, rec *confKeysRec) *httptest.ResponseRecorder {
	c.only("input", in, "mount", "endpoint", "token", "request", "keyStore", "betStore")
	mount := c.str(confKeysDef(in, "mount", "/boostx"))
	endpoint := c.str(in["endpoint"])
	field := map[string]string{"set-boost": "boosterJWT", "check-bet": "checkbetJWT", "verify-keys": "verifyKeysJWT"}[endpoint]
	defBody := ""
	if spec, ok := in["token"]; ok {
		c.token = c.buildToken(spec, "boostx")
		defBody = `{"` + field + `":"${token}"}`
	}
	roles := confKeysDef(in, "keyStore", map[string]any{
		"acme": map[string]any{"partnerPublicKeys": []any{"partner"}, "partnerPrivateKey": "partner", "boostxPublicKey": "boostx"},
	})
	bets := map[string]any{"setBoost": "ok", "checkBet": true}
	if m, ok := in["betStore"].(map[string]any); ok {
		c.only("betStore", m, "setBoost", "checkBet")
		maps.Copy(bets, m)
	}
	req, _ := in["request"].(map[string]any)
	c.only("request", req, "method", "path", "body", "bodyHex", "padTo", "padAt")
	method := c.str(confKeysDef(req, "method", "POST"))
	path := c.str(confKeysDef(req, "path", strings.TrimSuffix(mount, "/")+"/"+endpoint))

	var ks handlers.KeyStore
	if roles != nil {
		rec.ks = &confKeysStore{env: c.env, roles: roles.(map[string]any)}
		ks = rec.ks
	}
	rec.bs = &confKeysBets{setBoost: bets["setBoost"], checkBet: bets["checkBet"]}
	var bs handlers.BetStoreUpdater = rec.bs
	switch v := bets["checkBet"]; v {
	case "absent":
	case true, false, "error":
		bs = confKeysCheckingBets{rec.bs}
	default:
		c.t.Fatalf("unrepresentable input in an untagged case: a bool verdict cannot hold %v", v)
	}
	mux := http.NewServeMux()
	rec.construct(func() { handlers.Mount(mux, mount, bs, ks) })
	if rec.panicked {
		return nil
	}
	var body io.Reader
	if method != http.MethodGet && method != http.MethodHead {
		body = bytes.NewReader(c.body(req, defBody))
	}
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, httptest.NewRequest(method, path, body))
	return res
}

// --- expectations (FORMAT.md 5) ---

var confKeysCategories = []struct {
	name     string
	sentinel error
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

func confKeysCategoriesOf(err error) []string {
	var out []string
	for _, c := range confKeysCategories {
		if errors.Is(err, c.sentinel) {
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

// confKeysField reads the field named after the last claim-error phrase.
func confKeysField(msg string) string {
	i, n := -1, 0
	for _, p := range []string{"missing required claim: ", "invalid claim value: "} {
		if j := strings.LastIndex(msg, p); j > i {
			i, n = j, len(p)
		}
	}
	if i < 0 {
		return ""
	}
	rest := msg[i+n:]
	if end := strings.IndexFunc(rest, func(r rune) bool {
		return !(r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z')
	}); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

func confKeysCheckErr(err error, w map[string]any) error {
	if f, ok := w["failure"]; ok {
		var ne net.Error
		var ue *url.Error
		matched := map[any]bool{
			"cancelled": errors.Is(err, context.Canceled),
			"timeout":   errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout(),
			"network":   errors.As(err, &ue),
		}[f]
		if !matched {
			return fmt.Errorf("want failure %v, got %v", f, err)
		}
		return nil
	}
	var want []string
	list, _ := w["error"].([]any)
	for _, e := range list {
		want = append(want, e.(string))
	}
	sort.Strings(want)
	if got := confKeysCategoriesOf(err); !slices.Equal(got, want) {
		return fmt.Errorf("want error %v, got %v (%v)", want, got, err)
	}
	if f, ok := w["field"]; ok && confKeysField(err.Error()) != f {
		return fmt.Errorf("want field %v, got %q (%v)", f, confKeysField(err.Error()), err)
	}
	if r, ok := w["reason"]; ok && tokens.VerifyKeysReason(err) != r {
		return fmt.Errorf("want reason %v, got %q (%v)", r, tokens.VerifyKeysReason(err), err)
	}
	var ae *client.APIError
	if s, ok := w["status"]; ok && (!errors.As(err, &ae) || float64(ae.StatusCode) != s) {
		return fmt.Errorf("want status %v, got %v", s, err)
	}
	if m, ok := w["apiError"]; ok && (!errors.As(err, &ae) || ae.Message != m) {
		return fmt.Errorf("want apiError %q, got %v", m, err)
	}
	return nil
}

// confKeysMatch compares got with want, objects by the members want lists.
func confKeysMatch(got, want any, path string) error {
	switch w := want.(type) {
	case confKeysTime:
		g, ok := got.(float64)
		if !ok || g != math.Trunc(g) || g < w.at || g > w.at+w.slack {
			return fmt.Errorf("%s: got %v, want %.0f..+%.0f", path, got, w.at, w.slack)
		}
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: got %v, want an object", path, got)
		}
		for k, wv := range w {
			if err := confKeysMatch(g[k], wv, path+"."+k); err != nil {
				return err
			}
		}
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return fmt.Errorf("%s: got %v, want %v", path, got, w)
		}
		for i := range w {
			if err := confKeysMatch(g[i], w[i], fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	default:
		if got != want {
			return fmt.Errorf("%s: got %#v, want %#v", path, got, want)
		}
	}
	return nil
}

// checkBuilt makes the implicit checks of an accepted builder token, then
// compares payload and absent (FORMAT.md 5.3).
func (c *confKeysCtx) checkBuilt(tok string, signer any, ok map[string]any) error {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return fmt.Errorf("token has %d segments", len(parts))
	}
	dec := make([][]byte, 3)
	for i, s := range parts {
		b, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil || confKeysB64(b) != s {
			return fmt.Errorf("segment %d is not canonical base64url", i)
		}
		dec[i] = b
	}
	var header map[string]any
	if json.Unmarshal(dec[0], &header) != nil || len(header) != 2 || header["alg"] != "ES256" || header["typ"] != "JWT" {
		return fmt.Errorf("header %s", dec[0])
	}
	pub := c.pub(signer)
	if !confKeysVerify(pub, []byte(parts[0]+"."+parts[1]), parts[2]) {
		return errors.New("the JWS signature does not verify")
	}
	var roots map[string]json.RawMessage
	var payload map[string]any
	if json.Unmarshal(dec[1], &roots) != nil || json.Unmarshal(dec[1], &payload) != nil {
		return fmt.Errorf("payload %s", dec[1])
	}
	for name, r := range roots {
		var x struct {
			GID *tokens.GID `json:"gid"`
		}
		if json.Unmarshal(r, &x) == nil && x.GID != nil {
			if err := tokens.VerifyGID(x.GID, pub); err != nil {
				return fmt.Errorf("%s.gid: %w", name, err)
			}
		}
	}
	if w, has := ok["payload"]; has {
		if err := confKeysMatch(payload, w, "payload"); err != nil {
			return err
		}
	}
	absent, _ := ok["absent"].([]any)
	for _, p := range absent {
		parts := strings.Split(p.(string), ".")
		obj, _ := any(payload).(map[string]any)
		for _, k := range parts[:len(parts)-1] {
			obj, _ = obj[k].(map[string]any)
		}
		if _, has := obj[parts[len(parts)-1]]; has {
			return fmt.Errorf("payload member %s is present", p)
		}
	}
	return nil
}

func (c *confKeysCtx) checkOK(op string, in map[string]any, got any, ok map[string]any) error {
	switch op {
	case "key.loadPrivate", "key.loadPublic":
		pair, err := c.env.pair(ok["matches"])
		c.must(err)
		priv, pub := pair.priv, pair.pub
		if op == "key.loadPrivate" {
			priv = got.(*ecdsa.PrivateKey)
		} else {
			pub = got.(*ecdsa.PublicKey)
		}
		h := sha256.Sum256([]byte("probe"))
		sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
		if err != nil || !ecdsa.VerifyASN1(pub, h[:], sig) {
			return fmt.Errorf("the loaded key is not %v's (%v)", ok["matches"], err)
		}
		return nil
	case "gid.build":
		w := maps.Clone(ok)
		delete(w, "canonical")
		if err := confKeysMatch(got, w, "ok"); err != nil {
			return err
		}
		if canon, has := ok["canonical"].(string); has {
			sig := got.(map[string]any)["gid"].(map[string]any)["signature"].(string)
			if !confKeysVerify(c.pub(confKeysDef(in, "key", "partner")), []byte(canon), sig) {
				return errors.New("the signature does not cover the canonical bytes")
			}
		}
		return nil
	case "gamepass.create", "settlement.create":
		return c.checkBuilt(got.(string), confKeysDef(in, "key", "partner"), ok)
	case "verifykeys.createRequest":
		return c.checkBuilt(got.(string), confKeysDef(in, "key", "boostx"), ok)
	case "verifykeys.createResponse":
		return c.checkBuilt(got.(string), confKeysDef(in, "key", "partner"), ok)
	}
	return confKeysMatch(got, ok, "ok")
}

func (c *confKeysCtx) checkHTTP(res *httptest.ResponseRecorder, w map[string]any) error {
	if float64(res.Code) != w["status"] {
		return fmt.Errorf("status: got %d, want %v (body %s)", res.Code, w["status"], res.Body)
	}
	if a, ok := w["allow"]; ok && res.Header().Get("Allow") != a {
		return fmt.Errorf("allow: got %q, want %v", res.Header().Get("Allow"), a)
	}
	// routerMayAnswer: under Mount, ServeMux answers every such request (404, 405)
	// with its own body, so the body is not compared (FORMAT.md 6.7). The standalone
	// handlers' own 405 text is pinned by TestHandlers_MethodNotAllowed.
	if w["routerMayAnswer"] == true {
		return nil
	}
	var body any
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		if _, ok := w["body"]; ok || w["error"] != nil || w["errorPrefix"] != nil {
			return fmt.Errorf("body %q is not JSON", res.Body)
		}
	}
	obj, _ := body.(map[string]any)
	if e, ok := w["error"]; ok && (len(obj) != 1 || obj["error"] != e) {
		return fmt.Errorf("body: got %s, want {\"error\": %q}", res.Body, e)
	}
	if p, ok := w["errorPrefix"].(string); ok {
		msg, isStr := obj["error"].(string)
		if len(obj) != 1 || !isStr || !strings.HasPrefix(msg, p) {
			return fmt.Errorf("body: got %s, want an error starting %q", res.Body, p)
		}
	}
	if b, ok := w["body"]; ok && !reflect.DeepEqual(body, b) {
		return fmt.Errorf("body: got %s, want %v", res.Body, b)
	}
	return nil
}

func confKeysRunCase(t *testing.T, env *confKeysEnv, cs confKeysCase) {
	if confSkipNeeds(t, cs.Needs) {
		return
	}
	c := &confKeysCtx{t: t, env: env, now: time.Now().Unix()}
	c.prepareSigs(cs.Sigs)
	in := map[string]any{}
	for k, v := range cs.Input {
		if k == "token" || k == "request" || k == "response" {
			in[k] = v // text-field containers expand their own fields
		} else {
			in[k] = c.expand(v, false)
		}
	}
	want := cs.Want
	if cs.WantZeroValue != nil {
		want = cs.WantZeroValue
	}
	w := c.expand(want, true).(map[string]any)
	if cs.Op == "http.serve" {
		c.only("want", w, "status", "error", "errorPrefix", "body", "allow", "routerMayAnswer", "keyStoreCalled", "betStoreCalled", "at")
	} else {
		c.only("want", w, "ok", "error", "failure", "field", "reason", "status", "apiError", "at", "keyStoreCalled", "betStoreCalled", "requests")
	}

	rec := &confKeysRec{}
	got, err := c.run(cs.Op, in, rec)

	switch {
	case w["at"] == "construct":
		if !rec.panicked {
			t.Errorf("want a panic at construction, got %v, %v", got, err)
		}
		return
	case rec.panicked:
		t.Fatalf("unexpected panic at construction: %v", rec.panicValue)
	case cs.Op == "http.serve":
		if e := c.checkHTTP(got.(*httptest.ResponseRecorder), w); e != nil {
			t.Error(e)
		}
	case w["ok"] != nil:
		if err != nil {
			t.Errorf("want ok %v, got error %v (%v)", w["ok"], confKeysCategoriesOf(err), err)
		} else if e := c.checkOK(cs.Op, in, got, w["ok"].(map[string]any)); e != nil {
			t.Error(e)
		}
	default:
		if err != nil {
			if e := confKeysCheckErr(err, w); e != nil {
				t.Error(e)
			}
		} else {
			t.Errorf("want error %v%v, got ok %v", w["error"], w["failure"], got)
		}
	}

	if v, ok := w["keyStoreCalled"]; ok && (rec.ks == nil || rec.ks.called.Load() != v) {
		t.Errorf("keyStoreCalled: want %v", v)
	}
	if v, ok := w["betStoreCalled"]; ok && (rec.bs == nil || rec.bs.called.Load() != v) {
		t.Errorf("betStoreCalled: want %v", v)
	}
	if v, ok := w["requests"]; ok && (rec.tr == nil || float64(rec.tr.requests.Load()) != v) {
		t.Errorf("requests: want %v", v)
	}
}
