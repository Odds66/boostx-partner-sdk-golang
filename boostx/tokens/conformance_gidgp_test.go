package tokens_test

// Conformance runner for testdata/spec/gidgp.json (format: testdata/spec/FORMAT.md):
// buildGID, the gamepass builder, the X helpers, and the GID cases run through the CheckBet parser,
// the in-memory key store and the check-bet handler. It uses the exported API only.

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
	"maps"
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

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/handlers"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

const confGidgpDir = "../../testdata/spec/"

type confGidgpCase struct {
	Name          string
	Rules         []string
	Op            string
	Input         map[string]any
	Sigs          map[string]map[string]any
	Want          map[string]any
	WantZeroValue map[string]any
	Needs         []string `json:"needs"`
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

type confGidgpKeyPair struct {
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
}

// confGidgpSig is a GID signature; ids is set when partner, user and bet are known.
type confGidgpSig struct {
	partner, user, bet, text string
	ids                      bool
}

// confGidgpTime is an expanded time placeholder: in want it matches v..v+slack.
type confGidgpTime struct{ v, slack int64 }

type confGidgpCtx struct {
	now   int64
	sigs  map[string]confGidgpSig
	token string
}

type confGidgpRunner struct {
	keys  map[string]confGidgpKeyPair
	fixed map[string]confGidgpSig
}

func TestConformanceGidgp(t *testing.T) {
	var tk struct {
		Keys          map[string]map[string]string
		GIDSignatures []struct{ Key, Partner, User, Bet, Signature string }
	}
	confGidgpRead(t, confGidgpDir+"testkeys.json", &tk)
	r := &confGidgpRunner{keys: map[string]confGidgpKeyPair{}, fixed: map[string]confGidgpSig{}}
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
		r.keys[name] = confGidgpKeyPair{priv, pub}
	}
	// "@unusable" is the P-384 pair, loaded with the platform's own parsers.
	privBlock, _ := pem.Decode([]byte(tk.Keys["p384"]["pkcs8"]))
	pubBlock, _ := pem.Decode([]byte(tk.Keys["p384"]["spki"]))
	if privBlock == nil || pubBlock == nil {
		t.Fatal("p384 PEM does not decode")
	}
	p384Priv, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	p384Pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	r.keys["@unusable"] = confGidgpKeyPair{p384Priv.(*ecdsa.PrivateKey), p384Pub.(*ecdsa.PublicKey)}
	for _, s := range tk.GIDSignatures {
		name := map[string]string{"partner": "gid", "partner2": "gid2"}[s.Key]
		r.fixed[name] = confGidgpSig{s.Partner, s.User, s.Bet, s.Signature, true}
	}

	var file struct{ Cases []confGidgpCase }
	confGidgpRead(t, confGidgpDir+"gidgp.json", &file)
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) { r.run(t, c) })
	}
}

func confGidgpRead(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func (r *confGidgpRunner) run(t *testing.T, c confGidgpCase) {
	if confSkipNeeds(t, c.Needs) {
		return
	}
	ctx := &confGidgpCtx{now: time.Now().Unix(), sigs: maps.Clone(r.fixed)}
	for name, s := range c.Sigs {
		switch {
		case s["fixed"] != nil:
			ctx.sigs[name] = confGidgpSig{text: s["fixed"].(string)}
		case s["text"] != nil:
			k := r.privKey(t, s["key"])
			ctx.sigs[name] = confGidgpSig{text: confGidgpSign(t, k, r.expandText(t, s["text"].(string), ctx))}
		default:
			p, u, b := s["partner"].(string), s["user"].(string), s["bet"].(string)
			g, err := tokens.BuildGID(p, u, b, r.privKey(t, s["key"]))
			if err != nil {
				t.Fatalf("sig %s: BuildGID: %v", name, err)
			}
			ctx.sigs[name] = confGidgpSig{p, u, b, g.Signature, true}
		}
	}
	w := c.Want
	if c.WantZeroValue != nil {
		w = c.WantZeroValue
	}
	want := r.expandJSON(t, w, ctx).(map[string]any)
	// JSON values in input are expanded too; token specs and requests hold text fields, expanded where used.
	in := map[string]any{}
	for k, v := range c.Input {
		if k != "token" && k != "request" {
			v = r.expandJSON(t, v, ctx)
		}
		in[k] = v
	}
	switch c.Op {
	case "gid.build":
		r.runBuildGID(t, in, want)
	case "gamepass.create":
		r.runGamePass(t, in, want)
	case "x.floor", "x.player":
		r.runX(t, c.Op, in, want)
	case "checkbet.extract", "checkbet.parse":
		r.runCheckBet(t, c.Op, in, ctx, want)
	case "keystore.register":
		r.runKeyStore(t, in, want)
	case "http.serve":
		r.runHTTP(t, in, ctx, want)
	default:
		t.Fatalf("op %q is not supported by this runner", c.Op)
	}
}

// --- inputs ----------------------------------------------------------------------------------------------------------

// The readers below map an expanded input value onto a Go parameter: absent and null are the zero value, and
// a value the parameter's type cannot hold fails the case: confSkipNeeds has already skipped the tagged ones
// (FORMAT.md section 7).

func confGidgpString(t *testing.T, m map[string]any, k string) string {
	switch v := m[k].(type) {
	case nil:
		return ""
	case string:
		return v
	}
	t.Fatalf("unrepresentable input in an untagged case: %s %s cannot be passed as a Go string", k, confGidgpJSON(m[k]))
	return ""
}

func confGidgpFloat(t *testing.T, m map[string]any, k string) float64 {
	switch v := m[k].(type) {
	case nil:
		return 0
	case float64:
		return v
	}
	t.Fatalf("unrepresentable input in an untagged case: %s %s cannot be passed as a Go float64", k, confGidgpJSON(m[k]))
	return 0
}

func confGidgpInt(t *testing.T, m map[string]any, k string) int {
	switch v := m[k].(type) {
	case nil:
		return 0
	case float64:
		if v == math.Trunc(v) && math.Abs(v) <= 1<<53 {
			return int(v)
		}
	}
	t.Fatalf("unrepresentable input in an untagged case: %s %s cannot be passed as a Go int", k, confGidgpJSON(m[k]))
	return 0
}

func confGidgpBool(t *testing.T, m map[string]any, k string) bool {
	switch v := m[k].(type) {
	case nil:
		return false
	case bool:
		return v
	}
	t.Fatalf("unrepresentable input in an untagged case: %s %s cannot be passed as a Go bool", k, confGidgpJSON(m[k]))
	return false
}

// --- builders --------------------------------------------------------------------------------------------------------

func (r *confGidgpRunner) runBuildGID(t *testing.T, in, want map[string]any) {
	confGidgpOnly(t, want, "ok", "error", "field")
	keyName, priv := r.privParam(t, in, "partner")
	partner, user, bet := confGidgpString(t, in, "partner"), confGidgpString(t, in, "user"), confGidgpString(t, in, "bet")
	g, err := tokens.BuildGID(partner, user, bet, priv)
	var got map[string]any
	if err == nil {
		got = map[string]any{"gid": confGidgpGID(g)}
	}
	okWant, _ := want["ok"].(map[string]any)
	r.outcome(t, want, got, err, "canonical")
	if canonical, ok := okWant["canonical"].(string); ok {
		sig, decErr := base64.RawURLEncoding.Strict().DecodeString(g.Signature)
		h := sha256.Sum256([]byte(canonical))
		if decErr != nil || len(sig) != 64 || !ecdsa.Verify(r.keys[keyName].pub, h[:],
			new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			t.Fatalf("signature %q does not verify over the canonical bytes %q with %s", g.Signature, canonical, keyName)
		}
	}
}

func (r *confGidgpRunner) runGamePass(t *testing.T, in, want map[string]any) {
	confGidgpOnly(t, want, "ok", "error", "field")
	keyName, priv := r.privParam(t, in, "partner")
	p, ok := in["params"].(map[string]any)
	if !ok {
		t.Fatalf("unrepresentable input in an untagged case: params %s cannot be passed as a Go GamePassParams", confGidgpJSON(in["params"]))
	}
	params := tokens.GamePassParams{
		Partner:    confGidgpString(t, p, "partner"),
		User:       confGidgpString(t, p, "user"),
		Bet:        confGidgpString(t, p, "bet"),
		Amount:     confGidgpFloat(t, p, "amount"),
		Currency:   confGidgpString(t, p, "currency"),
		X:          confGidgpFloat(t, p, "x"),
		XMin:       confGidgpFloat(t, p, "xMin"),
		XMax:       confGidgpFloat(t, p, "xMax"),
		XDecimals:  confGidgpInt(t, p, "xDecimals"),
		EventTitle: confGidgpString(t, p, "eventTitle"),
		Demo:       confGidgpBool(t, p, "demo"),
	}
	for k := range p {
		if !slices.Contains([]string{"partner", "user", "bet", "amount", "currency", "x", "xMin", "xMax", "xDecimals", "eventTitle", "demo"}, k) {
			t.Fatalf("params member %q is not in the format", k)
		}
	}
	tok, err := tokens.CreateGamePassToken(priv, params)
	var got map[string]any
	if err == nil {
		got = map[string]any{"payload": r.builderPayload(t, tok, keyName)}
	}
	r.outcome(t, want, got, err)
}

// builderPayload runs the implicit checks of FORMAT.md 5.3 on an accepted builder token and returns its payload.
func (r *confGidgpRunner) builderPayload(t *testing.T, tok, keyName string) map[string]any {
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
	pub := r.keys[keyName].pub
	h := sha256.Sum256([]byte(seg[0] + "." + seg[1]))
	if len(raw[2]) != 64 || !ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(raw[2][:32]), new(big.Int).SetBytes(raw[2][32:])) {
		t.Errorf("builder signature does not verify with %s", keyName)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw[1], &payload); err != nil {
		t.Fatalf("builder payload: %v", err)
	}
	// A payload gid (one level down: gamepass.gid) must verify with the same key.
	for name, v := range payload {
		obj, _ := v.(map[string]any)
		gidRaw, ok := obj["gid"]
		if !ok {
			continue
		}
		b, _ := json.Marshal(gidRaw)
		var g tokens.GID
		if err := json.Unmarshal(b, &g); err != nil {
			t.Errorf("%s.gid does not decode: %v", name, err)
		} else if err := tokens.VerifyGID(&g, pub); err != nil {
			t.Errorf("%s.gid does not verify with %s: %v", name, keyName, err)
		}
	}
	return payload
}

// --- X helpers -------------------------------------------------------------------------------------------------------

func (r *confGidgpRunner) runX(t *testing.T, op string, in, want map[string]any) {
	confGidgpOnly(t, want, "ok", "error")
	var v float64
	if op == "x.floor" {
		v = tokens.FloorX(confGidgpFloat(t, in, "x"), confGidgpInt(t, in, "decimals"))
	} else {
		v = tokens.PlayerX(confGidgpFloat(t, in, "xBase"), confGidgpFloat(t, in, "boost"), confGidgpInt(t, in, "decimals"))
	}
	// The Go helpers return no error: NaN is how they refuse, read as invalid_claim (FORMAT.md 6.3).
	if math.IsNaN(v) {
		r.outcome(t, want, nil, fmt.Errorf("%w: NaN result", tokens.ErrInvalidClaim))
		return
	}
	r.outcome(t, want, map[string]any{"value": v}, nil)
}

// --- CheckBet --------------------------------------------------------------------------------------------------------

func (r *confGidgpRunner) runCheckBet(t *testing.T, op string, in map[string]any, ctx *confGidgpCtx, want map[string]any) {
	confGidgpOnly(t, want, "ok", "error", "field")
	spec, ok := in["token"].(map[string]any)
	if !ok {
		t.Fatal("input.token is required")
	}
	token := r.token(t, spec, ctx, "boostx")
	var got map[string]any
	var err error
	if op == "checkbet.extract" {
		var p string
		if p, err = tokens.ExtractCheckBetPartner(token); err == nil {
			got = map[string]any{"partner": p}
		}
	} else {
		boostxKey, partnerKeys := r.keys["boostx"].pub, []*ecdsa.PublicKey{r.keys["partner"].pub}
		if v, ok := in["boostxKey"]; ok {
			boostxKey = r.pub(t, v)
		}
		if v, ok := in["partnerKeys"]; ok {
			partnerKeys = r.pubs(t, v)
		}
		var cb *tokens.CheckBet
		if cb, err = tokens.ParseCheckBetTokenWithKeys(token, boostxKey, partnerKeys); err == nil {
			got = map[string]any{"gid": confGidgpGID(&cb.GID), "iat": float64(cb.IssuedAt)}
		}
	}
	r.outcome(t, want, got, err)
}

func confGidgpGID(g *tokens.GID) map[string]any {
	return map[string]any{"partner": g.Partner, "user": g.User, "bet": g.Bet, "signature": g.Signature}
}

// --- keystore.register -----------------------------------------------------------------------------------------------

func (r *confGidgpRunner) runKeyStore(t *testing.T, in, want map[string]any) {
	confGidgpOnly(t, want, "ok", "error", "field")
	ks := keys.NewMemoryKeyStore()
	partner := confGidgpString(t, in, "partner")
	priv, boostxPub := r.priv(t, in["partnerPrivateKey"]), r.pub(t, in["boostxPublicKey"])
	var err error
	if list, ok := in["partnerPublicKey"].([]any); ok {
		err = ks.RegisterWithPartnerPublicKeys(partner, r.pubs(t, list), priv, boostxPub)
	} else {
		err = ks.Register(partner, r.pub(t, in["partnerPublicKey"]), priv, boostxPub)
	}
	r.outcome(t, want, map[string]any{}, err)

	lookups, _ := in["lookups"].([]any)
	for i, l := range lookups {
		l := l.(map[string]any)
		lw, _ := l["want"].(map[string]any)
		p, _ := l["partner"].(string)
		var got map[string]any
		var lerr error
		switch l["method"] {
		case "partnerPublicKeys":
			var list []*ecdsa.PublicKey
			if list, lerr = ks.PartnerPublicKeys(context.Background(), p); lerr == nil {
				names := []any{}
				for _, k := range list {
					names = append(names, r.pubName(k))
				}
				got = map[string]any{"keys": names}
			}
		case "partnerPrivateKey":
			var k *ecdsa.PrivateKey
			if k, lerr = ks.PartnerPrivateKey(context.Background(), p); lerr == nil {
				got = map[string]any{"key": r.privName(k)}
			}
		case "boostxPublicKey":
			var k *ecdsa.PublicKey
			if k, lerr = ks.BoostxPublicKey(context.Background(), p); lerr == nil {
				got = map[string]any{"key": r.pubName(k)}
			}
		default:
			t.Fatalf("lookup method %v is not in the format", l["method"])
		}
		t.Logf("lookup %d: %v %q", i, l["method"], p)
		r.outcome(t, lw, got, lerr)
	}
}

func (r *confGidgpRunner) pubName(k *ecdsa.PublicKey) any {
	for name, kp := range r.keys {
		if k != nil && kp.pub.Equal(k) {
			return name
		}
	}
	return fmt.Sprintf("<unknown public key %p>", k)
}

func (r *confGidgpRunner) privName(k *ecdsa.PrivateKey) any {
	for name, kp := range r.keys {
		if k != nil && kp.priv.Equal(k) {
			return name
		}
	}
	return fmt.Sprintf("<unknown private key %p>", k)
}

// --- outcomes --------------------------------------------------------------------------------------------------------

var confGidgpSentinels = []struct {
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

// confGidgpCategories is the sorted taxonomy set of err. api_error is left out: no operation here calls the client.
func confGidgpCategories(err error) []string {
	var out []string
	for _, s := range confGidgpSentinels {
		if errors.Is(err, s.err) {
			out = append(out, s.name)
		}
	}
	slices.Sort(out)
	return out
}

var confGidgpFieldRE = regexp.MustCompile(`^[A-Za-z0-9_.]*`)

// confGidgpField reads the claim named after the last "missing required claim: " or "invalid claim value: ".
func confGidgpField(msg string) (string, bool) {
	at, rest := -1, ""
	for _, p := range []string{"missing required claim: ", "invalid claim value: "} {
		if i := strings.LastIndex(msg, p); i > at {
			at, rest = i, msg[i+len(p):]
		}
	}
	return confGidgpFieldRE.FindString(rest), at >= 0
}

// outcome compares a result or an error with want (FORMAT.md 5.1, 5.3). Members of want.ok named in skip are
// checked by the caller.
func (r *confGidgpRunner) outcome(t *testing.T, want, got map[string]any, err error, skip ...string) {
	t.Helper()
	if okWant, has := want["ok"].(map[string]any); has {
		if err != nil {
			t.Fatalf("want ok %s, got error %v (%v)", confGidgpJSON(okWant), confGidgpCategories(err), err)
		}
		for k, w := range okWant {
			switch {
			case slices.Contains(skip, k):
			case k == "absent":
				confGidgpAbsent(t, w, got["payload"])
			default:
				g, present := got[k]
				if !present {
					t.Fatalf("ok.%s: not in the result %s", k, confGidgpJSON(got))
				}
				if e := confGidgpMatch(g, w, "ok."+k, false); e != nil {
					t.Fatalf("%v (got %s)", e, confGidgpJSON(g))
				}
			}
		}
		return
	}
	wantErr, has := want["error"].([]any)
	if !has {
		t.Fatal("want holds neither ok nor error")
	}
	var wantSet []string
	for _, e := range wantErr {
		wantSet = append(wantSet, e.(string))
	}
	slices.Sort(wantSet)
	if err == nil {
		t.Fatalf("want error %v, got ok %s", wantSet, confGidgpJSON(got))
	}
	if gotSet := confGidgpCategories(err); !slices.Equal(gotSet, wantSet) {
		t.Fatalf("want error %v, got %v (%q)", wantSet, gotSet, err)
	}
	if f, has := want["field"]; has {
		if g, found := confGidgpField(err.Error()); !found || g != f {
			t.Fatalf("want field %v, got %q (%q)", f, g, err)
		}
	}
}

func confGidgpAbsent(t *testing.T, paths, payload any) {
	list, _ := paths.([]any)
	for _, p := range list {
		cur, present := payload, true
		for _, part := range strings.Split(p.(string), ".") {
			m, isObj := cur.(map[string]any)
			if cur, present = m[part]; !isObj || !present {
				present = false
				break
			}
		}
		if present {
			t.Fatalf("absent: %s is present in the payload (%s)", p, confGidgpJSON(payload))
		}
	}
}

// confGidgpMatch compares got with want as FORMAT.md 5.3 says; exact also refuses members want does not list.
func confGidgpMatch(got, want any, path string, exact bool) error {
	switch w := want.(type) {
	case confGidgpTime:
		g, ok := got.(float64)
		if !ok || g != math.Trunc(g) || int64(g) < w.v || int64(g) > w.v+w.slack {
			return fmt.Errorf("%s: got %s, want %d..%d", path, confGidgpJSON(got), w.v, w.v+w.slack)
		}
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return fmt.Errorf("%s: got %s, want %s", path, confGidgpJSON(got), confGidgpJSON(want))
		}
		for i := range w {
			if err := confGidgpMatch(g[i], w[i], fmt.Sprintf("%s[%d]", path, i), exact); err != nil {
				return err
			}
		}
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok || (exact && len(g) != len(w)) {
			return fmt.Errorf("%s: got %s, want %s", path, confGidgpJSON(got), confGidgpJSON(want))
		}
		for k, wv := range w {
			gv, present := g[k]
			if !present {
				return fmt.Errorf("%s.%s: missing", path, k)
			}
			if err := confGidgpMatch(gv, wv, path+"."+k, exact); err != nil {
				return err
			}
		}
	case float64:
		if g, ok := got.(float64); !ok || g != w {
			return fmt.Errorf("%s: got %v, want %v", path, got, want)
		}
	default:
		if got != want {
			return fmt.Errorf("%s: got %s, want %s", path, confGidgpJSON(got), confGidgpJSON(want))
		}
	}
	return nil
}

func confGidgpOnly(t *testing.T, want map[string]any, allowed ...string) {
	for k := range want {
		if !slices.Contains(allowed, k) {
			t.Fatalf("want member %q is not supported by this runner", k)
		}
	}
}

func confGidgpJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// --- http.serve ------------------------------------------------------------------------------------------------------

func (r *confGidgpRunner) runHTTP(t *testing.T, in map[string]any, ctx *confGidgpCtx, want map[string]any) {
	confGidgpOnly(t, want, "status", "error", "errorPrefix", "body", "allow", "routerMayAnswer",
		"setBoostArg", "checkBetArg", "keyStoreCalled", "betStoreCalled", "at")
	spec, hasToken := in["token"].(map[string]any)
	if hasToken {
		ctx.token = r.token(t, spec, ctx, "boostx")
	}
	endpoint, _ := in["endpoint"].(string)
	mount := "/boostx"
	if m, ok := in["mount"].(string); ok {
		mount = m
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
	if method != "GET" && method != "HEAD" {
		text := ""
		if hasToken {
			field := map[string]string{"set-boost": "boosterJWT", "check-bet": "checkbetJWT", "verify-keys": "verifyKeysJWT"}[endpoint]
			text = `{"` + field + `":"${token}"}`
		}
		if s, ok := req["body"].(string); ok {
			text = s
		}
		body = r.expandText(t, text, ctx)
		if h, ok := req["bodyHex"].(string); ok {
			var err error
			if body, err = hex.DecodeString(h); err != nil {
				t.Fatal(err)
			}
		}
		if n, ok := req["padTo"].(float64); ok && int(n) > len(body) {
			at := len(body)
			if a, ok := req["padAt"].(float64); ok {
				if at = int(a); at < 0 {
					at += len(body)
				}
			}
			body = slices.Concat(body[:at], bytes.Repeat([]byte(" "), int(n)-len(body)), body[at:])
		}
	}

	var keyStore handlers.KeyStore
	ks := &confGidgpKS{r: r, t: t, m: map[string]any{"acme": map[string]any{
		"partnerPublicKeys": []any{"partner"}, "partnerPrivateKey": "partner", "boostxPublicKey": "boostx",
	}}}
	if v, ok := in["keyStore"]; !ok {
		keyStore = ks
	} else if v != nil {
		ks.m = v.(map[string]any)
		keyStore = ks
	}
	bsIn := map[string]any{"setBoost": "ok", "checkBet": true}
	if v, ok := in["betStore"].(map[string]any); ok {
		maps.Copy(bsIn, v)
	}
	base := &confGidgpBS{setBoost: bsIn["setBoost"].(string)}
	if !slices.Contains([]string{"ok", "reject", "reject-wrapped", "error"}, base.setBoost) {
		t.Fatalf("betStore.setBoost %q is not in the format", base.setBoost)
	}
	var betStore handlers.BetStoreUpdater = base
	switch v := bsIn["checkBet"]; v {
	case "absent":
	case true, false, "error":
		betStore = &confGidgpCheckingBS{base, v}
	default:
		t.Fatalf("unrepresentable input in an untagged case: checkBet verdict %v cannot be returned by a Go BetStoreChecker", v)
	}

	mux := http.NewServeMux()
	panicked := func() (p any) {
		defer func() { p = recover() }()
		handlers.Mount(mux, mount, betStore, keyStore)
		return nil
	}()
	if want["at"] == "construct" {
		if panicked == nil {
			t.Fatal("want a construction panic, Mount returned")
		}
		return
	}
	if panicked != nil {
		t.Fatalf("Mount panicked: %v", panicked)
	}
	httpReq := httptest.NewRequest(method, path, nil)
	if body != nil {
		httpReq = httptest.NewRequest(method, path, bytes.NewReader(body))
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httpReq)
	got := fmt.Sprintf("%d %s", rec.Code, strings.TrimSpace(rec.Body.String()))

	if s, ok := want["status"].(float64); !ok || float64(rec.Code) != s {
		t.Fatalf("want status %v, got %s", want["status"], got)
	}
	if a, ok := want["allow"]; ok && rec.Header().Get("Allow") != a {
		t.Fatalf("want Allow %v, got %q", a, rec.Header().Get("Allow"))
	}
	// routerMayAnswer: under Mount, ServeMux answers every such request (404, 405)
	// with its own body, so the body is not compared (FORMAT.md 6.7). The standalone
	// handlers' own 405 text is pinned by TestHandlers_MethodNotAllowed.
	if want["routerMayAnswer"] != true {
		var parsed any
		jsonErr := json.Unmarshal(rec.Body.Bytes(), &parsed)
		if e, ok := want["error"]; ok {
			if jsonErr != nil || confGidgpMatch(parsed, map[string]any{"error": e}, "body", true) != nil {
				t.Fatalf("want body {\"error\": %q}, got %s", e, got)
			}
		}
		if p, ok := want["errorPrefix"].(string); ok {
			m, _ := parsed.(map[string]any)
			s, isString := m["error"].(string)
			if jsonErr != nil || len(m) != 1 || !isString || !strings.HasPrefix(s, p) {
				t.Fatalf("want body {\"error\": %q…}, got %s", p, got)
			}
		}
		if b, ok := want["body"]; ok {
			if jsonErr != nil || confGidgpMatch(parsed, b, "body", true) != nil {
				t.Fatalf("want body %s, got %s", confGidgpJSON(b), got)
			}
		}
	}
	if w, ok := want["setBoostArg"]; ok {
		if base.arg == nil {
			t.Fatal("want setBoost to receive a Booster, it was not called")
		}
		b := base.arg
		g := map[string]any{"gid": confGidgpGID(&b.GID), "round": float64(b.Round), "boost": b.Boost,
			"final": b.Final, "jackpot": b.Jackpot, "iat": float64(b.IssuedAt)}
		if e := confGidgpMatch(g, w, "setBoostArg", false); e != nil {
			t.Fatalf("%v (got %s)", e, confGidgpJSON(g))
		}
	}
	if w, ok := want["checkBetArg"]; ok {
		if base.gid == nil {
			t.Fatal("want checkBet to receive a GID, it was not called")
		}
		if e := confGidgpMatch(confGidgpGID(base.gid), w, "checkBetArg", false); e != nil {
			t.Fatal(e)
		}
	}
	if w, ok := want["keyStoreCalled"]; ok && ks.called.Load() != w {
		t.Fatalf("want keyStoreCalled %v, got %v (%s)", w, ks.called.Load(), got)
	}
	if w, ok := want["betStoreCalled"]; ok && base.called.Load() != w {
		t.Fatalf("want betStoreCalled %v, got %v (%s)", w, base.called.Load(), got)
	}
}

// confGidgpKS serves the format's role values: a key reference, null, {"error": …} or {"key": …, "delayMs": n}.
type confGidgpKS struct {
	r      *confGidgpRunner
	t      *testing.T
	m      map[string]any
	called atomic.Bool
}

func (k *confGidgpKS) lookup(ctx context.Context, partner, role string, invalid error) (any, error) {
	k.called.Store(true)
	entry, ok := k.m[partner].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %q", keys.ErrUnknownPartner, partner)
	}
	v := entry[role]
	if obj, ok := v.(map[string]any); ok {
		switch obj["error"] {
		case "unknown_partner":
			return nil, fmt.Errorf("%w: %q", keys.ErrUnknownPartner, partner)
		case "other":
			return nil, errors.New("key store failure")
		}
		d, _ := obj["delayMs"].(float64)
		select {
		case <-time.After(time.Duration(d) * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		v = obj["key"]
	}
	if v == nil {
		return nil, fmt.Errorf("%w: %s not given", invalid, role)
	}
	return v, nil
}

func (k *confGidgpKS) PartnerPublicKeys(ctx context.Context, partner string) ([]*ecdsa.PublicKey, error) {
	v, err := k.lookup(ctx, partner, "partnerPublicKeys", tokens.ErrInvalidPublicKey)
	if err != nil {
		return nil, err
	}
	return k.r.pubs(k.t, v), nil
}

func (k *confGidgpKS) PartnerPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error) {
	list, err := k.PartnerPublicKeys(ctx, partner)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%w: empty key list", tokens.ErrInvalidPublicKey)
	}
	return list[0], nil
}

func (k *confGidgpKS) PartnerPrivateKey(ctx context.Context, partner string) (*ecdsa.PrivateKey, error) {
	v, err := k.lookup(ctx, partner, "partnerPrivateKey", tokens.ErrInvalidPrivateKey)
	if err != nil {
		return nil, err
	}
	return k.r.priv(k.t, v), nil
}

func (k *confGidgpKS) BoostxPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error) {
	v, err := k.lookup(ctx, partner, "boostxPublicKey", tokens.ErrInvalidPublicKey)
	if err != nil {
		return nil, err
	}
	return k.r.pub(k.t, v), nil
}

type confGidgpBS struct {
	setBoost string
	called   atomic.Bool
	arg      *tokens.Booster
	gid      *tokens.GID
}

func (b *confGidgpBS) SetBoost(_ context.Context, booster *tokens.Booster) error {
	b.called.Store(true)
	b.arg = booster
	switch b.setBoost {
	case "reject":
		return handlers.ErrRoundRejected
	case "reject-wrapped":
		return fmt.Errorf("x: %w", handlers.ErrRoundRejected)
	case "error":
		return errors.New("bet store failure")
	}
	return nil
}

type confGidgpCheckingBS struct {
	*confGidgpBS
	verdict any
}

func (b *confGidgpCheckingBS) CheckBet(_ context.Context, gid *tokens.GID) (bool, error) {
	b.called.Store(true)
	b.gid = gid
	if v, ok := b.verdict.(bool); ok {
		return v, nil
	}
	return false, errors.New("bet store failure")
}

// --- keys ------------------------------------------------------------------------------------------------------------

// privParam reads input.key: left out is def, null is nil. It returns the key name for the builder checks.
func (r *confGidgpRunner) privParam(t *testing.T, in map[string]any, def string) (string, *ecdsa.PrivateKey) {
	ref, ok := in["key"]
	if !ok {
		ref = def
	}
	name, _ := ref.(string)
	return name, r.priv(t, ref)
}

func (r *confGidgpRunner) priv(t *testing.T, ref any) *ecdsa.PrivateKey {
	if ref == nil {
		return nil
	}
	return r.privKey(t, ref)
}

func (r *confGidgpRunner) privKey(t *testing.T, ref any) *ecdsa.PrivateKey {
	name, _ := ref.(string)
	kp, ok := r.keys[name]
	if !ok {
		t.Fatalf("bad private key reference %v", ref)
	}
	return kp.priv
}

func (r *confGidgpRunner) pub(t *testing.T, ref any) *ecdsa.PublicKey {
	if ref == nil {
		return nil
	}
	name, _ := ref.(string)
	kp, ok := r.keys[name]
	if !ok {
		t.Fatalf("bad public key reference %v", ref)
	}
	return kp.pub
}

func (r *confGidgpRunner) pubs(t *testing.T, ref any) []*ecdsa.PublicKey {
	list, ok := ref.([]any)
	if !ok {
		return []*ecdsa.PublicKey{r.pub(t, ref)}
	}
	out := []*ecdsa.PublicKey{}
	for _, x := range list {
		out = append(out, r.pub(t, x))
	}
	return out
}

// confGidgpSign is ES256 over data: base64url of the 64-byte r || s.
func confGidgpSign(t *testing.T, k *ecdsa.PrivateKey, data []byte) string {
	if k.Curve.Params().BitSize != 256 {
		t.Fatal("a token or signature can be signed with a P-256 key only")
	}
	h := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

// --- token specs -----------------------------------------------------------------------------------------------------

func (r *confGidgpRunner) token(t *testing.T, spec map[string]any, ctx *confGidgpCtx, defaultKey string) string {
	if raw, ok := spec["raw"].(string); ok {
		return string(r.expandText(t, raw, ctx))
	}
	must := func(s string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	segment := func(hexKey, textKey, def string) string {
		var b []byte
		if h, ok := spec[hexKey].(string); ok {
			var err error
			if b, err = hex.DecodeString(h); err != nil {
				t.Fatal(err)
			}
		} else if s, ok := spec[textKey].(string); ok {
			b = r.expandText(t, s, ctx)
		} else if def != "" {
			b = []byte(def)
		} else {
			t.Fatalf("token spec has no %s", textKey)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	h := must(confGidgpApply(segment("headerHex", "header", `{"alg":"ES256","typ":"JWT"}`), spec["headerSegment"]))
	p := must(confGidgpApply(segment("payloadHex", "payload", ""), spec["payloadSegment"]))
	keyRef := any(defaultKey)
	if k, ok := spec["key"]; ok {
		keyRef = k
	}
	priv := r.privKey(t, keyRef)
	transforms, _ := spec["signature"].([]any)
	for i := 0; ; i++ {
		s, err := confGidgpApply(confGidgpSign(t, priv, []byte(h+"."+p)), spec["signature"])
		if err != nil && i < 63 && slices.Contains(transforms, any("std-alphabet")) {
			continue // a signature with neither '-' nor '_': sign again
		}
		return must(confGidgpApply(h+"."+p+"."+must(s, err), spec["transform"]))
	}
}

const confGidgpAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func confGidgpApply(text string, list any) (string, error) {
	transforms, _ := list.([]any)
	for _, tr := range transforms {
		out, err := confGidgpTransform(text, tr)
		if err != nil {
			return "", err
		}
		if out == text {
			return "", fmt.Errorf("transform %v leaves %q unchanged", tr, text)
		}
		text = out
	}
	return text, nil
}

func confGidgpTransform(text string, tr any) (string, error) {
	switch tr {
	case "pad":
		if len(text)%4 == 0 {
			return text + "====", nil
		}
		return text + strings.Repeat("=", 4-len(text)%4), nil
	case "std-alphabet":
		return strings.NewReplacer("-", "+", "_", "/").Replace(text), nil
	case "trailing-bits":
		if len(text)%4 == 0 {
			return "", fmt.Errorf("trailing-bits on %q, whose length is a multiple of 4", text)
		}
		i := strings.IndexByte(confGidgpAlphabet, text[len(text)-1])
		if i < 0 || i == 63 {
			return "", fmt.Errorf("trailing-bits on %q", text)
		}
		return text[:len(text)-1] + confGidgpAlphabet[i+1:i+2], nil
	case "empty":
		return "", nil
	case "zero":
		return base64.RawURLEncoding.EncodeToString(make([]byte, 64)), nil
	case "flip":
		b, err := base64.RawURLEncoding.DecodeString(text)
		if err != nil || len(b) == 0 {
			return "", fmt.Errorf("flip on %q", text)
		}
		b[0] ^= 1
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	m, _ := tr.(map[string]any)
	num := func(k string) int { f, _ := m[k].(float64); return int(f) }
	runes := []rune(text)
	if s, ok := m["insert"].(string); ok {
		at := num("at")
		if at < 0 {
			at += len(runes)
		}
		return string(runes[:at]) + s + string(runes[at:]), nil
	}
	if s, ok := m["append"].(string); ok {
		return text + s, nil
	}
	if _, ok := m["truncate"]; ok {
		return string(runes[:len(runes)-num("truncate")]), nil
	}
	if _, ok := m["segments"]; ok {
		parts := strings.Split(text, ".")
		return strings.Join(parts[:min(num("segments"), len(parts))], "."), nil
	}
	return "", fmt.Errorf("unknown transform %v", tr)
}

// --- placeholders ----------------------------------------------------------------------------------------------------

var (
	confGidgpPlaceholder = regexp.MustCompile(`\$\{([^}]*)\}`)
	confGidgpWhole       = regexp.MustCompile(`^\$\{([^}]*)\}$`)
	confGidgpTimeExpr    = regexp.MustCompile(`^now(Ms)?(?:([+-])(\d+))?$`)
)

func (r *confGidgpRunner) expandText(t *testing.T, text string, ctx *confGidgpCtx) []byte {
	out, last := []byte{}, 0
	for _, m := range confGidgpPlaceholder.FindAllStringSubmatchIndex(text, -1) {
		out = append(out, text[last:m[0]]...)
		expr := text[m[2]:m[3]]
		if h, ok := strings.CutPrefix(expr, "hex:"); ok {
			b, err := hex.DecodeString(h)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, b...)
		} else {
			switch v := r.resolve(t, expr, ctx).(type) {
			case confGidgpTime:
				out = strconv.AppendInt(out, v.v, 10)
			case string:
				out = append(out, v...)
			}
		}
		last = m[1]
	}
	return append(out, text[last:]...)
}

func (r *confGidgpRunner) resolve(t *testing.T, expr string, ctx *confGidgpCtx) any {
	if m := confGidgpTimeExpr.FindStringSubmatch(expr); m != nil {
		v, slack := ctx.now, int64(5)
		if m[1] != "" {
			v, slack = ctx.now*1000, 5000
		}
		if m[2] != "" {
			n, _ := strconv.ParseInt(m[3], 10, 64)
			if m[2] == "-" {
				n = -n
			}
			v += n
		}
		return confGidgpTime{v, slack}
	}
	if name, ok := strings.CutPrefix(expr, "sig:"); ok {
		s, ok := ctx.sigs[name]
		if !ok {
			t.Fatalf("unknown signature %q", name)
		}
		return s.text
	}
	if expr == "gid" || strings.HasPrefix(expr, "gid:") {
		name := strings.TrimPrefix(strings.TrimPrefix(expr, "gid"), ":")
		if name == "" {
			name = "gid"
		}
		s := ctx.sigs[name]
		if !s.ids {
			t.Fatalf("${%s} needs a signature with ids", expr)
		}
		b, err := json.Marshal(tokens.GID{Partner: s.partner, User: s.user, Bet: s.bet, Signature: s.text})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	switch expr {
	case "token":
		return confGidgpEscape(ctx.token)
	case "$":
		return "$"
	}
	t.Fatalf("unknown placeholder ${%s}", expr)
	return nil
}

// confGidgpEscape escapes ", \ and C0 controls, and nothing else.
func confGidgpEscape(s string) string {
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

// expandJSON expands a JSON value of input or want: whole-string placeholders, {"$number": …} and
// {"$illFormed": s}, which Go spells as s followed by the byte 0xFF.
func (r *confGidgpRunner) expandJSON(t *testing.T, v any, ctx *confGidgpCtx) any {
	switch v := v.(type) {
	case string:
		if m := confGidgpWhole.FindStringSubmatch(v); m != nil {
			return r.resolve(t, m[1], ctx)
		}
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = r.expandJSON(t, x, ctx)
		}
		return out
	case map[string]any:
		if n, ok := v["$number"].(string); ok && len(v) == 1 {
			f, known := map[string]float64{"NaN": math.NaN(), "Infinity": math.Inf(1), "-Infinity": math.Inf(-1), "-0": math.Copysign(0, -1)}[n]
			if !known {
				t.Fatalf("$number %q is not in the format", n)
			}
			return f
		}
		if s, ok := v["$illFormed"].(string); ok && len(v) == 1 {
			return s + "\xff"
		}
		out := make(map[string]any, len(v))
		for k, x := range v {
			out[k] = r.expandJSON(t, x, ctx)
		}
		return out
	}
	return v
}
