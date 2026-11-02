package client_test

// Runner for the language-neutral conformance vectors of the settle group
// (testdata/spec/settle.json): the settlement builder, the settlement
// client and the in-memory key store's private-key role. The vector format is
// described in testdata/spec/FORMAT.md. Only the exported API is used.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/client"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

const confSettleDir = "../../testdata/spec/"

type confSettleCase struct {
	Name          string                     `json:"name"`
	Op            string                     `json:"op"`
	Input         map[string]json.RawMessage `json:"input"`
	Want          json.RawMessage            `json:"want"`
	WantZeroValue json.RawMessage            `json:"wantZeroValue"`
	Needs         []string                   `json:"needs"`
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

// confSettleWant holds every outcome member this group uses; any other member
// fails the case, so nothing in a vector is silently left unchecked.
type confSettleWant struct {
	OK             json.RawMessage `json:"ok"`
	Error          []string        `json:"error"`
	Failure        string          `json:"failure"`
	Field          *string         `json:"field"`
	Reason         *string         `json:"reason"`
	Status         *int            `json:"status"`
	APIError       *string         `json:"apiError"`
	At             string          `json:"at"`
	Requests       *int            `json:"requests"`
	Request        json.RawMessage `json:"request"`
	KeyStoreCalled *bool           `json:"keyStoreCalled"`
}

type confSettleKeySet struct {
	priv map[string]*ecdsa.PrivateKey
	pub  map[string]*ecdsa.PublicKey
}

func TestConformanceSettle(t *testing.T) {
	ks := confSettleLoadKeys(t)
	var file struct {
		Group string           `json:"group"`
		Cases []confSettleCase `json:"cases"`
	}
	confSettleReadJSON(t, "settle.json", &file)
	if file.Group != "settle" || len(file.Cases) == 0 {
		t.Fatalf("settle.json: group %q with %d cases", file.Group, len(file.Cases))
	}
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if confSkipNeeds(t, c.Needs) {
				return
			}
			now := time.Now().Unix() // read once per case, before anything is built
			wantRaw := c.Want
			if c.WantZeroValue != nil {
				wantRaw = c.WantZeroValue // Go's parameter structs cannot express an absent member
			}
			w := confSettleDecodeWant(t, wantRaw)
			switch c.Op {
			case "settlement.create":
				confSettleRunCreate(t, ks, c, w, now)
			case "client.submit":
				confSettleRunClient(t, ks, c, w, now)
			case "keystore.register":
				confSettleRunRegister(t, ks, c, w)
			default:
				t.Fatalf("harness: unsupported op %q", c.Op)
			}
		})
	}
}

func confSettleReadJSON(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(confSettleDir + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func confSettleDecodeWant(t *testing.T, raw json.RawMessage) confSettleWant {
	t.Helper()
	var w confSettleWant
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&w); err != nil {
		t.Fatalf("harness: want: %v", err)
	}
	n := 0
	for _, set := range []bool{w.OK != nil, w.Error != nil, w.Failure != ""} {
		if set {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("harness: want needs exactly one of ok, error, failure: %s", raw)
	}
	return w
}

func confSettleCheckInput(t *testing.T, c confSettleCase, known ...string) {
	t.Helper()
	for k := range c.Input {
		if !slices.Contains(known, k) {
			t.Fatalf("harness: input member %q is not supported for %s", k, c.Op)
		}
	}
}

func confSettleLoadKeys(t *testing.T) confSettleKeySet {
	t.Helper()
	var tk struct {
		Keys map[string]map[string]string `json:"keys"`
	}
	confSettleReadJSON(t, "testkeys.json", &tk)
	ks := confSettleKeySet{priv: map[string]*ecdsa.PrivateKey{}, pub: map[string]*ecdsa.PublicKey{}}
	for name, forms := range tk.Keys {
		if name == "p384" {
			// "@unusable": a P-384 pair, loaded with the platform's own parsers.
			b, _ := pem.Decode([]byte(forms["pkcs8"]))
			p, err := x509.ParsePKCS8PrivateKey(b.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			b, _ = pem.Decode([]byte(forms["spki"]))
			q, err := x509.ParsePKIXPublicKey(b.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			ks.priv["@unusable"], ks.pub["@unusable"] = p.(*ecdsa.PrivateKey), q.(*ecdsa.PublicKey)
			continue
		}
		p, err := keys.LoadPrivateKeyFromPEM([]byte(forms["pkcs8"]))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		q, err := keys.LoadPublicKeyFromPEM([]byte(forms["spki"]))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ks.priv[name], ks.pub[name] = p, q
	}
	return ks
}

// privRef resolves a private-key reference: left out is def ("" for no
// key), null is no key. It returns the key and its name.
func (ks confSettleKeySet) privRef(raw json.RawMessage, def string) (*ecdsa.PrivateKey, string, error) {
	name := def
	if raw != nil {
		if string(raw) == "null" {
			return nil, "", nil
		}
		if err := json.Unmarshal(raw, &name); err != nil {
			return nil, "", fmt.Errorf("harness: key reference %s", raw)
		}
	}
	if name == "" {
		return nil, "", nil
	}
	k, ok := ks.priv[name]
	if !ok {
		return nil, "", fmt.Errorf("harness: unknown key %q", name)
	}
	return k, name, nil
}

func (ks confSettleKeySet) pubRef(raw json.RawMessage) (*ecdsa.PublicKey, error) {
	if raw == nil || string(raw) == "null" {
		return nil, nil
	}
	var name string
	if err := json.Unmarshal(raw, &name); err != nil {
		return nil, fmt.Errorf("harness: key reference %s", raw)
	}
	k, ok := ks.pub[name]
	if !ok {
		return nil, fmt.Errorf("harness: unknown key %q", name)
	}
	return k, nil
}

// --- Placeholders and special values -----------------------------------------

var (
	confSettlePlaceholder = regexp.MustCompile(`\$\{([^}]*)\}`)
	confSettleWhole       = regexp.MustCompile(`^\$\{([^}]*)\}$`)
	confSettleTimeExpr    = regexp.MustCompile(`^(now|nowMs)(?:([+-])(\d+))?$`)
)

// confSettleTime evaluates a time expression and returns its value and the
// slack a want comparison allows after it.
func confSettleTime(expr string, now int64) (v, slack int64, ok bool) {
	m := confSettleTimeExpr.FindStringSubmatch(expr)
	if m == nil {
		return 0, 0, false
	}
	v, slack = now, 5
	if m[1] == "nowMs" {
		v, slack = now*1000, 5000
	}
	if m[2] != "" {
		n, err := strconv.ParseInt(m[3], 10, 64)
		if err != nil {
			return 0, 0, false
		}
		if m[2] == "-" {
			n = -n
		}
		v += n
	}
	return v, slack, true
}

// confSettleText expands a text field into bytes.
func confSettleText(s string, now int64) ([]byte, error) {
	var out []byte
	last := 0
	for _, m := range confSettlePlaceholder.FindAllStringSubmatchIndex(s, -1) {
		out = append(out, s[last:m[0]]...)
		expr := s[m[2]:m[3]]
		switch {
		case expr == "$":
			out = append(out, '$')
		case strings.HasPrefix(expr, "hex:"):
			b, err := hex.DecodeString(expr[4:])
			if err != nil {
				return nil, fmt.Errorf("harness: %s: %v", expr, err)
			}
			out = append(out, b...)
		default:
			v, _, ok := confSettleTime(expr, now)
			if !ok {
				return nil, fmt.Errorf("harness: unsupported placeholder ${%s}", expr)
			}
			out = strconv.AppendInt(out, v, 10)
		}
		last = m[1]
	}
	return append(out, s[last:]...), nil
}

func confSettleDecode(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, errors.New("trailing data after JSON value")
	}
	return v, nil
}

// confSettleExpand applies section 3 and 4 of the format to a decoded input
// value: a whole-string placeholder becomes its value, {"$number"} a float64,
// {"$illFormed"} the string plus the byte 0xFF.
func confSettleExpand(v any, now int64) (any, error) {
	switch x := v.(type) {
	case string:
		m := confSettleWhole.FindStringSubmatch(x)
		if m == nil {
			return x, nil
		}
		if t, _, ok := confSettleTime(m[1], now); ok {
			return json.Number(strconv.FormatInt(t, 10)), nil
		}
		if m[1] == "$" {
			return "$", nil
		}
		return nil, fmt.Errorf("harness: unsupported placeholder %s", x)
	case map[string]any:
		if len(x) == 1 {
			if s, ok := x["$number"].(string); ok {
				switch s {
				case "NaN":
					return math.NaN(), nil
				case "Infinity":
					return math.Inf(1), nil
				case "-Infinity":
					return math.Inf(-1), nil
				case "-0":
					return math.Copysign(0, -1), nil
				}
				return nil, fmt.Errorf("harness: $number %q", s)
			}
			if s, ok := x["$illFormed"].(string); ok {
				return s + "\xff", nil
			}
		}
		for k, e := range x {
			ev, err := confSettleExpand(e, now)
			if err != nil {
				return nil, err
			}
			x[k] = ev
		}
	case []any:
		for i, e := range x {
			ev, err := confSettleExpand(e, now)
			if err != nil {
				return nil, err
			}
			x[i] = ev
		}
	}
	return v, nil
}

func confSettleInput(raw json.RawMessage, now int64) (any, error) {
	v, err := confSettleDecode(raw)
	if err != nil {
		return nil, fmt.Errorf("harness: %v", err)
	}
	return confSettleExpand(v, now)
}

// confSettleParams builds SettlementParams. Absent and null members are the
// zero value; a value Go's types cannot hold is returned as the reason it
// is unrepresentable, which fails the case (FORMAT.md section 7).
func confSettleParams(raw json.RawMessage, now int64) (tokens.SettlementParams, string, error) {
	var p tokens.SettlementParams
	if raw == nil {
		return p, "", nil
	}
	v, err := confSettleInput(raw, now)
	if err != nil {
		return p, "", err
	}
	if v == nil {
		return p, "params null: SettlementParams is a struct and cannot be missing", nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return p, "", fmt.Errorf("harness: params %s", raw)
	}
	known := []string{"partner", "user", "bet", "status", "amount", "currency", "version", "xSettle", "settledAt"}
	for k := range m {
		if !slices.Contains(known, k) {
			return p, "", fmt.Errorf("harness: unknown param %q", k)
		}
	}
	var bad []string
	str := func(k string) string {
		switch x := m[k].(type) {
		case nil:
			return ""
		case string:
			return x
		}
		bad = append(bad, k)
		return ""
	}
	num := func(k string) float64 {
		switch x := m[k].(type) {
		case nil:
			return 0
		case float64:
			return x
		case json.Number:
			if f, err := x.Float64(); err == nil {
				return f
			}
		}
		bad = append(bad, k)
		return 0
	}
	integer := func(k string) int64 {
		switch x := m[k].(type) {
		case nil:
			return 0
		case float64:
			if x == 0 { // -0
				return 0
			}
		case json.Number:
			if n, err := strconv.ParseInt(string(x), 10, 64); err == nil {
				return n
			}
		}
		bad = append(bad, k)
		return 0
	}
	p.Partner, p.User, p.Bet = str("partner"), str("user"), str("bet")
	p.Status, p.Currency = str("status"), str("currency")
	p.Amount = num("amount")
	p.Version = integer("version")
	p.SettledAt = integer("settledAt")
	if m["xSettle"] != nil {
		x := num("xSettle")
		p.XSettle = &x
	}
	if len(bad) > 0 {
		slices.Sort(bad)
		return p, "Go's SettlementParams cannot hold the given " + strings.Join(bad, ", "), nil
	}
	return p, "", nil
}

// --- Outcome checks ------------------------------------------------------------

var confSettleCategoryErrs = []struct {
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

func confSettleCategories(err error) []string {
	out := []string{}
	for _, c := range confSettleCategoryErrs {
		if errors.Is(err, c.err) {
			out = append(out, c.name)
		}
	}
	var ae *client.APIError
	if errors.As(err, &ae) {
		out = append(out, "api_error")
	}
	slices.Sort(out)
	return out
}

// confSettleField reads the claim an error names: the longest run of
// [A-Za-z0-9_.] after the last "missing required claim: " or "invalid claim value: ".
func confSettleField(msg string) string {
	start := -1
	for _, phrase := range []string{"missing required claim: ", "invalid claim value: "} {
		if i := strings.LastIndex(msg, phrase); i >= 0 && i+len(phrase) > start {
			start = i + len(phrase)
		}
	}
	if start < 0 {
		return ""
	}
	end := start
	for end < len(msg) {
		c := msg[end]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' {
			end++
			continue
		}
		break
	}
	return msg[start:end]
}

func confSettleCheckOutcome(t *testing.T, w confSettleWant, err error) {
	t.Helper()
	switch {
	case w.OK != nil:
		if err != nil {
			t.Errorf("want ok, got error %q (categories %v)", err, confSettleCategories(err))
		}
	case w.Error != nil:
		if err == nil {
			t.Errorf("want error %v, got ok", w.Error)
			return
		}
		want := slices.Sorted(slices.Values(w.Error))
		if got := confSettleCategories(err); !slices.Equal(got, want) {
			t.Errorf("want error categories %v, got %v (%q)", want, got, err)
		}
		if w.Field != nil {
			if got := confSettleField(err.Error()); got != *w.Field {
				t.Errorf("want field %q, got %q (%q)", *w.Field, got, err)
			}
		}
		if w.Reason != nil {
			if got := tokens.VerifyKeysReason(err); got != *w.Reason {
				t.Errorf("want reason %q, got %q", *w.Reason, got)
			}
		}
		var ae *client.APIError
		isAPI := errors.As(err, &ae)
		if w.Status != nil && (!isAPI || ae.StatusCode != *w.Status) {
			t.Errorf("want API status %d, got %q", *w.Status, err)
		}
		if w.APIError != nil && (!isAPI || ae.Message != *w.APIError) {
			t.Errorf("want API error text %q, got %q", *w.APIError, err)
		}
	case w.Failure != "":
		if err == nil {
			t.Errorf("want failure %q, got ok", w.Failure)
			return
		}
		var ne net.Error
		var ue *url.Error
		var ok bool
		switch w.Failure {
		case "cancelled":
			ok = errors.Is(err, context.Canceled)
		case "timeout":
			ok = errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
		case "network":
			ok = errors.As(err, &ue)
		default:
			t.Fatalf("harness: failure %q", w.Failure)
		}
		if !ok {
			t.Errorf("want failure %q, got %q (%T)", w.Failure, err, err)
		}
		if cats := confSettleCategories(err); len(cats) > 0 {
			t.Errorf("want failure %q passed through unchanged, got categories %v (%q)", w.Failure, cats, err)
		}
	}
}

func confSettleNum(v any) (float64, bool) {
	switch x := v.(type) {
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		return f, err == nil
	case float64:
		return x, true
	}
	return 0, false
}

// confSettleMatch compares got against want as section 5.3 says: listed members
// only, arrays by length and element, numbers with ==, time expressions as a range.
func confSettleMatch(want, got any, now int64, path string) error {
	switch w := want.(type) {
	case string:
		if m := confSettleWhole.FindStringSubmatch(w); m != nil {
			if v, slack, ok := confSettleTime(m[1], now); ok {
				n, isNum := confSettleNum(got)
				if !isNum || n != math.Trunc(n) || n < float64(v) || n > float64(v+slack) {
					return fmt.Errorf("%s: want %s in [%d, %d], got %v", path, w, v, v+slack, got)
				}
				return nil
			}
			b, err := confSettleText(w, now)
			if err != nil {
				return err
			}
			w = string(b)
		}
		if g, ok := got.(string); !ok || g != w {
			return fmt.Errorf("%s: want %q, got %#v", path, w, got)
		}
	case json.Number:
		wn, _ := strconv.ParseFloat(string(w), 64)
		if gn, ok := confSettleNum(got); !ok || gn != wn {
			return fmt.Errorf("%s: want %s, got %v", path, w, got)
		}
	case bool:
		if g, ok := got.(bool); !ok || g != w {
			return fmt.Errorf("%s: want %v, got %#v", path, w, got)
		}
	case nil:
		if got != nil {
			return fmt.Errorf("%s: want null, got %#v", path, got)
		}
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: want an object, got %#v", path, got)
		}
		for k, wv := range w {
			gv, present := g[k]
			if !present {
				return fmt.Errorf("%s.%s: missing", path, k)
			}
			if err := confSettleMatch(wv, gv, now, path+"."+k); err != nil {
				return err
			}
		}
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return fmt.Errorf("%s: want %d elements, got %#v", path, len(w), got)
		}
		for i := range w {
			if err := confSettleMatch(w[i], g[i], now, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("harness: %s: unsupported want value %#v", path, want)
	}
	return nil
}

// confSettleVerifyToken runs the implicit builder checks of section 5.3 and
// returns the decoded payload.
func confSettleVerifyToken(tok string, pub *ecdsa.PublicKey) (any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token has %d segments", len(parts))
	}
	var seg [3][]byte
	for i, p := range parts {
		b, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil || base64.RawURLEncoding.EncodeToString(b) != p {
			return nil, fmt.Errorf("segment %d is not canonical base64url", i)
		}
		seg[i] = b
	}
	var hdr map[string]any
	if json.Unmarshal(seg[0], &hdr) != nil || len(hdr) != 2 || hdr["alg"] != "ES256" || hdr["typ"] != "JWT" {
		return nil, fmt.Errorf("header is %s", seg[0])
	}
	if pub == nil {
		return nil, errors.New("harness: no public key to verify the token with")
	}
	if len(seg[2]) != 64 {
		return nil, fmt.Errorf("signature is %d bytes", len(seg[2]))
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(seg[2][:32]), new(big.Int).SetBytes(seg[2][32:])})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.VerifyASN1(pub, h[:], der) {
		return nil, errors.New("signature does not verify")
	}
	payload, err := confSettleDecode(seg[1])
	if err != nil {
		return nil, fmt.Errorf("payload: %v", err)
	}
	root, ok := payload.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("payload is %s", seg[1])
	}
	for name, member := range root {
		obj, _ := member.(map[string]any)
		g, ok := obj["gid"].(map[string]any)
		if !ok {
			continue
		}
		s := func(k string) string { v, _ := g[k].(string); return v }
		gid := tokens.GID{Partner: s("partner"), User: s("user"), Bet: s("bet"), Signature: s("signature")}
		if err := tokens.VerifyGID(&gid, pub); err != nil {
			return nil, fmt.Errorf("%s.gid does not verify: %w", name, err)
		}
	}
	return payload, nil
}

// confSettleCheckToken checks a built token and compares its payload with the
// "payload" and "absent" members of want.
func confSettleCheckToken(t *testing.T, tok string, pub *ecdsa.PublicKey, want map[string]json.RawMessage, now int64) {
	t.Helper()
	payload, err := confSettleVerifyToken(tok, pub)
	if err != nil {
		t.Errorf("builder check: %v", err)
		return
	}
	if raw, ok := want["payload"]; ok {
		wv, err := confSettleDecode(raw)
		if err != nil {
			t.Fatalf("harness: %v", err)
		}
		if err := confSettleMatch(wv, payload, now, "payload"); err != nil {
			t.Error(err)
		}
	}
	if raw, ok := want["absent"]; ok {
		var paths []string
		if err := json.Unmarshal(raw, &paths); err != nil {
			t.Fatalf("harness: absent: %v", err)
		}
		for _, p := range paths {
			var cur any = payload
			present := true
			for _, k := range strings.Split(p, ".") {
				m, ok := cur.(map[string]any)
				if cur, ok = m[k]; !ok {
					present = false
					break
				}
			}
			if present {
				t.Errorf("payload member %s must be absent, got %#v", p, cur)
			}
		}
	}
	for k := range want {
		if k != "payload" && k != "absent" {
			t.Fatalf("harness: unsupported builder ok member %q", k)
		}
	}
}

// --- settlement.create --------------------------------------------------------

func confSettleRunCreate(t *testing.T, ks confSettleKeySet, c confSettleCase, w confSettleWant, now int64) {
	confSettleCheckInput(t, c, "key", "params")
	key, name, err := ks.privRef(c.Input["key"], "partner")
	if err != nil {
		t.Fatal(err)
	}
	params, unrep, err := confSettleParams(c.Input["params"], now)
	if err != nil {
		t.Fatal(err)
	}
	if unrep != "" {
		t.Fatal("unrepresentable input in an untagged case: " + unrep)
	}
	tok, err := tokens.CreateSettlementToken(key, params)
	confSettleCheckOutcome(t, w, err)
	if w.OK != nil && err == nil {
		var okm map[string]json.RawMessage
		if err := json.Unmarshal(w.OK, &okm); err != nil {
			t.Fatalf("harness: ok: %v", err)
		}
		confSettleCheckToken(t, tok, ks.pub[name], okm, now)
	}
}

// --- keystore.register --------------------------------------------------------

func confSettleRunRegister(t *testing.T, ks confSettleKeySet, c confSettleCase, w confSettleWant) {
	confSettleCheckInput(t, c, "partner", "partnerPublicKey", "partnerPrivateKey", "boostxPublicKey", "lookups")
	var partner string
	if err := json.Unmarshal(c.Input["partner"], &partner); err != nil {
		t.Fatalf("harness: partner: %v", err)
	}
	priv, _, err := ks.privRef(c.Input["partnerPrivateKey"], "")
	if err != nil {
		t.Fatal(err)
	}
	boostxPub, err := ks.pubRef(c.Input["boostxPublicKey"])
	if err != nil {
		t.Fatal(err)
	}
	store := keys.NewMemoryKeyStore()
	var regErr error
	if raw := c.Input["partnerPublicKey"]; len(raw) > 0 && raw[0] == '[' {
		var refs []json.RawMessage
		if err := json.Unmarshal(raw, &refs); err != nil {
			t.Fatalf("harness: partnerPublicKey: %v", err)
		}
		list := []*ecdsa.PublicKey{}
		for _, r := range refs {
			k, err := ks.pubRef(r)
			if err != nil {
				t.Fatal(err)
			}
			list = append(list, k)
		}
		regErr = store.RegisterWithPartnerPublicKeys(partner, list, priv, boostxPub)
	} else {
		k, err := ks.pubRef(raw)
		if err != nil {
			t.Fatal(err)
		}
		regErr = store.Register(partner, k, priv, boostxPub)
	}
	confSettleCheckOutcome(t, w, regErr)

	var lookups []struct {
		Method  string          `json:"method"`
		Partner string          `json:"partner"`
		Want    json.RawMessage `json:"want"`
	}
	if raw := c.Input["lookups"]; raw != nil {
		if err := json.Unmarshal(raw, &lookups); err != nil {
			t.Fatalf("harness: lookups: %v", err)
		}
	}
	ctx := context.Background()
	for i, l := range lookups {
		lw := confSettleDecodeWant(t, l.Want)
		var ok struct {
			Key  string   `json:"key"`
			Keys []string `json:"keys"`
		}
		if lw.OK != nil {
			if err := json.Unmarshal(lw.OK, &ok); err != nil {
				t.Fatalf("harness: lookup ok: %v", err)
			}
		}
		t.Run(fmt.Sprintf("lookup-%d-%s-%q", i, l.Method, l.Partner), func(t *testing.T) {
			switch l.Method {
			case "partnerPrivateKey":
				k, err := store.PartnerPrivateKey(ctx, l.Partner)
				confSettleCheckOutcome(t, lw, err)
				if lw.OK != nil && err == nil && (k == nil || !k.Equal(ks.priv[ok.Key])) {
					t.Errorf("want key %q, got another", ok.Key)
				}
			case "boostxPublicKey":
				k, err := store.BoostxPublicKey(ctx, l.Partner)
				confSettleCheckOutcome(t, lw, err)
				if lw.OK != nil && err == nil && (k == nil || !k.Equal(ks.pub[ok.Key])) {
					t.Errorf("want key %q, got another", ok.Key)
				}
			case "partnerPublicKeys":
				got, err := store.PartnerPublicKeys(ctx, l.Partner)
				confSettleCheckOutcome(t, lw, err)
				if lw.OK != nil && err == nil {
					same := len(got) == len(ok.Keys)
					for j := 0; same && j < len(got); j++ {
						same = got[j].Equal(ks.pub[ok.Keys[j]])
					}
					if !same {
						t.Errorf("want keys %v, got %d other keys", ok.Keys, len(got))
					}
				}
			default:
				t.Fatalf("harness: lookup method %q", l.Method)
			}
		})
	}
}

// --- client.submit ------------------------------------------------------------

// confSettleRole is one partner's answer from the fake client key store.
type confSettleRole struct {
	key   *ecdsa.PrivateKey
	err   error
	delay time.Duration
}

type confSettleKeyStore struct {
	roles  map[string]confSettleRole
	called atomic.Bool
}

func (s *confSettleKeyStore) PartnerPrivateKey(ctx context.Context, partner string) (*ecdsa.PrivateKey, error) {
	s.called.Store(true)
	r, ok := s.roles[partner]
	if !ok {
		return nil, fmt.Errorf("%w %q", keys.ErrUnknownPartner, partner)
	}
	if r.delay > 0 {
		timer := time.NewTimer(r.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return r.key, r.err
}

// role resolves a role value of the client key store and returns the name of
// the key it answers with, if any.
func (ks confSettleKeySet) role(raw json.RawMessage) (confSettleRole, string, error) {
	if string(raw) == "null" {
		return confSettleRole{err: fmt.Errorf("%w: no partner private key", tokens.ErrInvalidPrivateKey)}, "", nil
	}
	if raw[0] == '"' {
		k, name, err := ks.privRef(raw, "")
		return confSettleRole{key: k}, name, err
	}
	var obj struct {
		Error   *string         `json:"error"`
		Key     json.RawMessage `json:"key"`
		DelayMs int             `json:"delayMs"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&obj); err != nil {
		return confSettleRole{}, "", fmt.Errorf("harness: role value %s: %v", raw, err)
	}
	if obj.Error != nil {
		switch *obj.Error {
		case "unknown_partner":
			return confSettleRole{err: fmt.Errorf("%w: from the store", keys.ErrUnknownPartner)}, "", nil
		case "other":
			return confSettleRole{err: errors.New("key store unavailable")}, "", nil
		}
		return confSettleRole{}, "", fmt.Errorf("harness: role error %q", *obj.Error)
	}
	k, name, err := ks.privRef(obj.Key, "")
	return confSettleRole{key: k, delay: time.Duration(obj.DelayMs) * time.Millisecond}, name, err
}

type confSettleResponse struct {
	Status       *int              `json:"status"`
	Headers      map[string]string `json:"headers"`
	Body         *string           `json:"body"`
	BodyHex      *string           `json:"bodyHex"`
	PadTo        int               `json:"padTo"`
	PadAt        *int              `json:"padAt"`
	DelayMs      int               `json:"delayMs"`
	BodyDelayMs  int               `json:"bodyDelayMs"`
	NetworkError bool              `json:"networkError"`
}

type confSettleSent struct {
	url, method, contentType string
	body                     []byte
	redirected               bool
}

// confSettleTransport serves the canned response and records every request.
type confSettleTransport struct {
	status  int
	header  http.Header
	body    []byte
	delay   time.Duration
	bodyLag time.Duration
	netErr  bool

	mu   sync.Mutex
	sent []confSettleSent
}

func (f *confSettleTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}
	f.mu.Lock()
	f.sent = append(f.sent, confSettleSent{
		url:         req.URL.String(),
		method:      req.Method,
		contentType: req.Header.Get("Content-Type"),
		body:        body,
		redirected:  req.Response != nil, // set by http.Client on a request that follows a redirect
	})
	f.mu.Unlock()
	if f.netErr {
		return nil, errors.New("connection refused")
	}
	ctx := req.Context()
	if f.delay > 0 {
		timer := time.NewTimer(f.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &http.Response{
		Status:     fmt.Sprintf("%d %s", f.status, http.StatusText(f.status)),
		StatusCode: f.status,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     f.header.Clone(),
		Body:       &confSettleBody{r: bytes.NewReader(f.body), lag: f.bodyLag, ctx: ctx},
		Request:    req,
	}, nil
}

// confSettleBody waits lag before its first byte, ending early when ctx is done.
type confSettleBody struct {
	r      *bytes.Reader
	lag    time.Duration
	ctx    context.Context
	waited bool
}

func (b *confSettleBody) Read(p []byte) (int, error) {
	if !b.waited {
		b.waited = true
		if b.lag > 0 {
			timer := time.NewTimer(b.lag)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-b.ctx.Done():
				return 0, b.ctx.Err()
			}
		}
	}
	return b.r.Read(p)
}

func (b *confSettleBody) Close() error { return nil }

func confSettleRunClient(t *testing.T, ks confSettleKeySet, c confSettleCase, w confSettleWant, now int64) {
	confSettleCheckInput(t, c, "params", "keyStore", "options", "cancel", "response")
	params, unrep, err := confSettleParams(c.Input["params"], now)
	if err != nil {
		t.Fatal(err)
	}

	// Options.
	opts := map[string]json.RawMessage{}
	if raw := c.Input["options"]; raw != nil {
		if err := json.Unmarshal(raw, &opts); err != nil {
			t.Fatalf("harness: options: %v", err)
		}
	}
	var copts []client.Option
	if raw, ok := opts["baseURL"]; !ok {
		copts = append(copts, client.WithBaseURL("https://boostx.test"))
	} else if string(raw) != "null" {
		var base string
		if err := json.Unmarshal(raw, &base); err != nil {
			t.Fatalf("harness: baseURL: %v", err)
		}
		copts = append(copts, client.WithBaseURL(base))
	}
	var timeout time.Duration
	if raw, ok := opts["timeoutMs"]; ok {
		v, err := confSettleInput(raw, now)
		if err != nil {
			t.Fatal(err)
		}
		if v != nil {
			ms, isNum := confSettleNum(v)
			if !isNum {
				t.Fatalf("harness: timeoutMs %s", raw)
			}
			if math.IsNaN(ms) || math.IsInf(ms, 0) {
				unrep = fmt.Sprintf("timeoutMs %v cannot be an http.Client Timeout (time.Duration)", ms)
			}
			timeout = time.Duration(ms * float64(time.Millisecond))
		}
	}
	for k := range opts {
		if k != "baseURL" && k != "timeoutMs" {
			t.Fatalf("harness: unsupported option %q", k)
		}
	}
	if unrep != "" {
		t.Fatal("unrepresentable input in an untagged case: " + unrep)
	}

	// Key store; the request token is checked against the key it hands out.
	var store client.KeyStore
	fake := &confSettleKeyStore{roles: map[string]confSettleRole{}}
	signer := ""
	ksRaw, present := c.Input["keyStore"]
	if !present {
		ksRaw = json.RawMessage(`{"acme":"partner"}`)
	}
	if string(ksRaw) != "null" {
		var entries map[string]json.RawMessage
		if err := json.Unmarshal(ksRaw, &entries); err != nil {
			t.Fatalf("harness: keyStore: %v", err)
		}
		for p, rv := range entries {
			r, name, err := ks.role(rv)
			if err != nil {
				t.Fatal(err)
			}
			fake.roles[p] = r
			if p == params.Partner {
				signer = name
			}
		}
		store = fake
	}

	// Canned response.
	var resp confSettleResponse
	if raw := c.Input["response"]; raw != nil {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(&resp); err != nil {
			t.Fatalf("harness: response: %v", err)
		}
	}
	tr := &confSettleTransport{
		status:  200,
		header:  http.Header{"Content-Type": {"application/json"}},
		delay:   time.Duration(resp.DelayMs) * time.Millisecond,
		bodyLag: time.Duration(resp.BodyDelayMs) * time.Millisecond,
		netErr:  resp.NetworkError,
	}
	if resp.Status != nil {
		tr.status = *resp.Status
	}
	if resp.Headers != nil {
		tr.header = http.Header{}
		for k, v := range resp.Headers {
			tr.header.Set(k, v)
		}
	}
	switch {
	case resp.Body != nil:
		if tr.body, err = confSettleText(*resp.Body, now); err != nil {
			t.Fatal(err)
		}
	case resp.BodyHex != nil:
		if tr.body, err = hex.DecodeString(*resp.BodyHex); err != nil {
			t.Fatalf("harness: bodyHex: %v", err)
		}
	}
	if n := resp.PadTo - len(tr.body); n > 0 {
		at := len(tr.body)
		if resp.PadAt != nil {
			if at = *resp.PadAt; at < 0 {
				at += len(tr.body)
			}
		}
		tr.body = slices.Insert(tr.body, at, bytes.Repeat([]byte{' '}, n)...)
	}
	copts = append(copts, client.WithHTTPClient(&http.Client{Transport: tr, Timeout: timeout}))

	// Cancellation handle.
	var ctx context.Context // "cancel": null passes a nil context
	if raw, ok := c.Input["cancel"]; !ok {
		ctx = context.Background()
	} else if string(raw) != "null" {
		var cancelBefore string
		var cancelAfter struct {
			AfterMs *int `json:"afterMs"`
		}
		cctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		switch {
		case json.Unmarshal(raw, &cancelBefore) == nil && cancelBefore == "before":
			cancel()
		case json.Unmarshal(raw, &cancelAfter) == nil && cancelAfter.AfterMs != nil:
			timer := time.AfterFunc(time.Duration(*cancelAfter.AfterMs)*time.Millisecond, cancel)
			defer timer.Stop()
		default:
			t.Fatalf("harness: cancel %s", raw)
		}
		ctx = cctx
	}

	var cl *client.Client
	var panicked any
	func() {
		defer func() { panicked = recover() }()
		cl = client.New(store, copts...)
	}()
	if w.At == "construct" {
		if panicked == nil {
			t.Errorf("want client.New to panic, it returned a client")
		}
		return
	}
	if w.At != "" {
		t.Fatalf("harness: at %q", w.At)
	}
	if panicked != nil {
		t.Fatalf("client.New panicked: %v", panicked)
	}

	err = cl.SubmitSettlement(ctx, params)
	confSettleCheckOutcome(t, w, err)

	tr.mu.Lock()
	sent := slices.Clone(tr.sent)
	tr.mu.Unlock()
	for _, s := range sent {
		if s.redirected {
			t.Errorf("the SDK followed a redirect to %s", s.url)
		}
	}
	if w.Requests != nil && len(sent) != *w.Requests {
		t.Errorf("want %d requests, got %d", *w.Requests, len(sent))
	}
	if w.KeyStoreCalled != nil && fake.called.Load() != *w.KeyStoreCalled {
		t.Errorf("want keyStoreCalled %v, got %v", *w.KeyStoreCalled, fake.called.Load())
	}
	if w.Request != nil {
		confSettleCheckRequest(t, w.Request, sent, ks.pub[signer], now)
	}
}

func confSettleCheckRequest(t *testing.T, raw json.RawMessage, sent []confSettleSent, pub *ecdsa.PublicKey, now int64) {
	t.Helper()
	var want map[string]json.RawMessage
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("harness: request: %v", err)
	}
	if len(sent) != 1 {
		t.Errorf("want one request to compare, got %d", len(sent))
		return
	}
	s := sent[0]
	got := map[string]string{"url": s.url, "method": s.method, "contentType": s.contentType}
	tokenWant := map[string]json.RawMessage{}
	for k, v := range want {
		switch k {
		case "url", "method", "contentType":
			var w string
			if err := json.Unmarshal(v, &w); err != nil {
				t.Fatalf("harness: request.%s: %v", k, err)
			}
			if got[k] != w {
				t.Errorf("request %s: want %q, got %q", k, w, got[k])
			}
		case "payload", "absent":
			tokenWant[k] = v
		default:
			t.Fatalf("harness: unsupported request member %q", k)
		}
	}
	var body map[string]json.RawMessage
	var tok string
	if err := json.Unmarshal(s.body, &body); err != nil || len(body) != 1 || json.Unmarshal(body["settlementJWT"], &tok) != nil {
		t.Errorf("request body must be {\"settlementJWT\": <token>}, got %s", s.body)
		return
	}
	confSettleCheckToken(t, tok, pub, tokenWant, now)
}
