package tokens_test

// Conformance runner for testdata/spec/inbound.json (format: testdata/spec/FORMAT.md).
// It uses the exported API only.

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

const confInboundDir = "../../testdata/spec/"

type confInboundCase struct {
	Name          string
	Rules         []string
	Op            string
	Input         map[string]any
	Sigs          map[string]map[string]any
	Want          map[string]any
	WantZeroValue map[string]any
	Needs         []string `json:"needs"`
}

type confInboundKeyPair struct {
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
}

// confInboundSig is a GID signature; ids is set when partner, user and bet are known.
type confInboundSig struct {
	partner, user, bet, text string
	ids                      bool
}

// confInboundTime is an expanded time placeholder: in want it matches v..v+slack.
type confInboundTime struct{ v, slack int64 }

type confInboundCtx struct {
	now   int64
	sigs  map[string]confInboundSig
	token string
}

type confInboundRunner struct {
	keys  map[string]confInboundKeyPair
	fixed map[string]confInboundSig
}

func TestConformanceInbound(t *testing.T) {
	var tk struct {
		Keys          map[string]map[string]string
		GIDSignatures []struct{ Key, Partner, User, Bet, Signature string }
	}
	confInboundRead(t, confInboundDir+"testkeys.json", &tk)
	r := &confInboundRunner{keys: map[string]confInboundKeyPair{}, fixed: map[string]confInboundSig{}}
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
		r.keys[name] = confInboundKeyPair{priv, pub}
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
	r.keys["@unusable"] = confInboundKeyPair{p384Priv.(*ecdsa.PrivateKey), p384Pub.(*ecdsa.PublicKey)}
	for _, s := range tk.GIDSignatures {
		name := map[string]string{"partner": "gid", "partner2": "gid2"}[s.Key]
		r.fixed[name] = confInboundSig{s.Partner, s.User, s.Bet, s.Signature, true}
	}

	var file struct{ Cases []confInboundCase }
	confInboundRead(t, confInboundDir+"inbound.json", &file)
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) { r.run(t, c) })
	}
}

func confInboundRead(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func (r *confInboundRunner) run(t *testing.T, c confInboundCase) {
	if confSkipNeeds(t, c.Needs) {
		return
	}
	ctx := &confInboundCtx{now: time.Now().Unix(), sigs: maps.Clone(r.fixed)}
	for name, s := range c.Sigs {
		switch {
		case s["fixed"] != nil:
			ctx.sigs[name] = confInboundSig{text: s["fixed"].(string)}
		case s["text"] != nil:
			k := r.privKey(t, s["key"])
			ctx.sigs[name] = confInboundSig{text: confInboundSign(t, k, r.expandText(t, s["text"].(string), ctx))}
		default:
			p, u, b := s["partner"].(string), s["user"].(string), s["bet"].(string)
			g, err := tokens.BuildGID(p, u, b, r.privKey(t, s["key"]))
			if err != nil {
				t.Fatalf("sig %s: BuildGID: %v", name, err)
			}
			ctx.sigs[name] = confInboundSig{p, u, b, g.Signature, true}
		}
	}
	w := c.Want
	if c.WantZeroValue != nil {
		w = c.WantZeroValue
	}
	want := r.expandWant(t, w, ctx).(map[string]any)
	switch c.Op {
	case "booster.extract", "booster.parse", "checkbet.extract", "checkbet.parse":
		r.runToken(t, c, ctx, want)
	case "http.serve":
		r.runHTTP(t, c, ctx, want)
	default:
		t.Fatalf("op %q is not supported by this runner", c.Op)
	}
}

// --- inbound token operations ------------------------------------------------------------------------------------

func (r *confInboundRunner) runToken(t *testing.T, c confInboundCase, ctx *confInboundCtx, want map[string]any) {
	confInboundOnly(t, want, "ok", "error", "field")
	spec, ok := c.Input["token"].(map[string]any)
	if !ok {
		t.Fatal("input.token is required")
	}
	token := r.token(t, spec, ctx, "boostx")
	boostxKey, partnerKeys := r.keys["boostx"].pub, []*ecdsa.PublicKey{r.keys["partner"].pub}
	if v, ok := c.Input["boostxKey"]; ok {
		boostxKey = confInboundMust[*ecdsa.PublicKey](t)(r.pub(v))
	}
	if v, ok := c.Input["partnerKeys"]; ok {
		partnerKeys = confInboundMust[[]*ecdsa.PublicKey](t)(r.pubs(v))
	}

	var got any
	var err error
	switch c.Op {
	case "booster.extract":
		var p string
		p, err = tokens.ExtractBoosterPartner(token)
		got = map[string]any{"partner": p}
	case "checkbet.extract":
		var p string
		p, err = tokens.ExtractCheckBetPartner(token)
		got = map[string]any{"partner": p}
	case "booster.parse":
		var b *tokens.Booster
		if b, err = tokens.ParseBoosterTokenWithKeys(token, boostxKey, partnerKeys); err == nil {
			got = confInboundBooster(b)
		}
	case "checkbet.parse":
		var cb *tokens.CheckBet
		if cb, err = tokens.ParseCheckBetTokenWithKeys(token, boostxKey, partnerKeys); err == nil {
			got = map[string]any{"gid": confInboundGID(&cb.GID), "iat": float64(cb.IssuedAt)}
		}
	}

	if okWant, has := want["ok"]; has {
		if err != nil {
			t.Fatalf("want ok %v, got error [%s] %q", confInboundJSON(okWant), strings.Join(confInboundCategories(err), " "), err)
		}
		if e := confInboundMatch(got, okWant, "ok", false); e != nil {
			t.Fatalf("%v (got %s)", e, confInboundJSON(got))
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
		t.Fatalf("want error %v, got ok %s", wantSet, confInboundJSON(got))
	}
	if gotSet := confInboundCategories(err); !slices.Equal(gotSet, wantSet) {
		t.Fatalf("want error %v, got %v (%q)", wantSet, gotSet, err)
	}
	if f, has := want["field"]; has {
		if got, found := confInboundField(err); !found || got != f {
			t.Fatalf("want field %v, got %q (%q)", f, got, err)
		}
	}
}

func confInboundGID(g *tokens.GID) map[string]any {
	return map[string]any{"partner": g.Partner, "user": g.User, "bet": g.Bet, "signature": g.Signature}
}

func confInboundBooster(b *tokens.Booster) map[string]any {
	return map[string]any{
		"gid": confInboundGID(&b.GID), "round": float64(b.Round), "boost": b.Boost,
		"final": b.Final, "jackpot": b.Jackpot, "iat": float64(b.IssuedAt),
	}
}

var confInboundSentinels = []struct {
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

// confInboundCategories is the sorted taxonomy set of err. api_error is left out: no inbound parser can raise one.
func confInboundCategories(err error) []string {
	var out []string
	for _, s := range confInboundSentinels {
		if errors.Is(err, s.err) {
			out = append(out, s.name)
		}
	}
	slices.Sort(out)
	return out
}

// confInboundField reads the claim named after the last "missing required claim: " or "invalid claim value: ".
func confInboundField(err error) (string, bool) {
	msg, start := err.Error(), -1
	for _, phrase := range []string{"missing required claim: ", "invalid claim value: "} {
		if i := strings.LastIndex(msg, phrase); i >= 0 && i+len(phrase) > start {
			start = i + len(phrase)
		}
	}
	if start < 0 {
		return "", false
	}
	end := start
	for end < len(msg) && (msg[end] == '_' || msg[end] == '.' || ('0' <= msg[end] && msg[end] <= '9') ||
		('a' <= msg[end]|0x20 && msg[end]|0x20 <= 'z')) {
		end++
	}
	return msg[start:end], true
}

// --- http.serve ----------------------------------------------------------------------------------------------------

func (r *confInboundRunner) runHTTP(t *testing.T, c confInboundCase, ctx *confInboundCtx, want map[string]any) {
	confInboundOnly(t, want, "status", "error", "errorPrefix", "body", "allow", "routerMayAnswer",
		"setBoostArg", "checkBetArg", "keyStoreCalled", "betStoreCalled", "at")
	in := c.Input
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
			body = confInboundMust[[]byte](t)(hex.DecodeString(h))
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
	ks := &confInboundKS{r: r, m: map[string]any{"acme": map[string]any{
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
	base := &confInboundBS{setBoost: bsIn["setBoost"].(string)}
	if !slices.Contains([]string{"ok", "reject", "reject-wrapped", "error"}, base.setBoost) {
		t.Fatalf("betStore.setBoost %q is not in the format", base.setBoost)
	}
	var betStore handlers.BetStoreUpdater = base
	switch v := bsIn["checkBet"]; v {
	case "absent":
	case true, false, "error":
		betStore = &confInboundCheckingBS{base, v}
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
	var httpReq *http.Request
	if body == nil {
		httpReq = httptest.NewRequest(method, path, nil)
	} else {
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
			if jsonErr != nil || confInboundMatch(parsed, map[string]any{"error": e}, "body", true) != nil {
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
			if jsonErr != nil || confInboundMatch(parsed, b, "body", true) != nil {
				t.Fatalf("want body %s, got %s", confInboundJSON(b), got)
			}
		}
	}
	if w, ok := want["setBoostArg"]; ok {
		if base.arg == nil {
			t.Fatal("want setBoost to receive a Booster, it was not called")
		}
		if e := confInboundMatch(confInboundBooster(base.arg), w, "setBoostArg", false); e != nil {
			t.Fatalf("%v (got %s)", e, confInboundJSON(confInboundBooster(base.arg)))
		}
	}
	if w, ok := want["checkBetArg"]; ok {
		if base.gid == nil {
			t.Fatal("want checkBet to receive a GID, it was not called")
		}
		if e := confInboundMatch(confInboundGID(base.gid), w, "checkBetArg", false); e != nil {
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

// confInboundKS serves the format's role values: a key reference, null, {"error": …} or {"key": …, "delayMs": n}.
type confInboundKS struct {
	r      *confInboundRunner
	m      map[string]any
	called atomic.Bool
}

func (k *confInboundKS) lookup(ctx context.Context, partner, role string, invalid error) (any, error) {
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

func (k *confInboundKS) PartnerPublicKeys(ctx context.Context, partner string) ([]*ecdsa.PublicKey, error) {
	v, err := k.lookup(ctx, partner, "partnerPublicKeys", tokens.ErrInvalidPublicKey)
	if err != nil {
		return nil, err
	}
	return k.r.pubs(v)
}

func (k *confInboundKS) PartnerPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error) {
	list, err := k.PartnerPublicKeys(ctx, partner)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%w: empty key list", tokens.ErrInvalidPublicKey)
	}
	return list[0], nil
}

func (k *confInboundKS) PartnerPrivateKey(ctx context.Context, partner string) (*ecdsa.PrivateKey, error) {
	v, err := k.lookup(ctx, partner, "partnerPrivateKey", tokens.ErrInvalidPrivateKey)
	if err != nil {
		return nil, err
	}
	name, _ := v.(string)
	kp, ok := k.r.keys[name]
	if !ok {
		return nil, fmt.Errorf("bad key reference %v", v)
	}
	return kp.priv, nil
}

func (k *confInboundKS) BoostxPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error) {
	v, err := k.lookup(ctx, partner, "boostxPublicKey", tokens.ErrInvalidPublicKey)
	if err != nil {
		return nil, err
	}
	return k.r.pub(v)
}

type confInboundBS struct {
	setBoost string
	called   atomic.Bool
	arg      *tokens.Booster
	gid      *tokens.GID
}

func (b *confInboundBS) SetBoost(_ context.Context, booster *tokens.Booster) error {
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

type confInboundCheckingBS struct {
	*confInboundBS
	verdict any
}

func (b *confInboundCheckingBS) CheckBet(_ context.Context, gid *tokens.GID) (bool, error) {
	b.called.Store(true)
	b.gid = gid
	if v, ok := b.verdict.(bool); ok {
		return v, nil
	}
	return false, errors.New("bet store failure")
}

// --- keys ------------------------------------------------------------------------------------------------------------

func (r *confInboundRunner) pub(ref any) (*ecdsa.PublicKey, error) {
	if ref == nil {
		return nil, nil
	}
	name, _ := ref.(string)
	kp, ok := r.keys[name]
	if !ok {
		return nil, fmt.Errorf("bad key reference %v", ref)
	}
	return kp.pub, nil
}

func (r *confInboundRunner) pubs(ref any) ([]*ecdsa.PublicKey, error) {
	list, ok := ref.([]any)
	if !ok {
		k, err := r.pub(ref)
		return []*ecdsa.PublicKey{k}, err
	}
	out := []*ecdsa.PublicKey{}
	for _, x := range list {
		k, err := r.pub(x)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

func (r *confInboundRunner) privKey(t *testing.T, ref any) *ecdsa.PrivateKey {
	name, _ := ref.(string)
	kp, ok := r.keys[name]
	if !ok {
		t.Fatalf("bad private key reference %v", ref)
	}
	return kp.priv
}

func confInboundMust[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

// confInboundSign is ES256 over data: base64url of the 64-byte r || s.
func confInboundSign(t *testing.T, k *ecdsa.PrivateKey, data []byte) string {
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

func (r *confInboundRunner) token(t *testing.T, spec map[string]any, ctx *confInboundCtx, defaultKey string) string {
	if raw, ok := spec["raw"].(string); ok {
		return string(r.expandText(t, raw, ctx))
	}
	segment := func(hexKey, textKey, def string) string {
		var b []byte
		if h, ok := spec[hexKey].(string); ok {
			b = confInboundMust[[]byte](t)(hex.DecodeString(h))
		} else if s, ok := spec[textKey].(string); ok {
			b = r.expandText(t, s, ctx)
		} else if def != "" {
			b = []byte(def)
		} else {
			t.Fatalf("token spec has no %s", textKey)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	h := confInboundMust[string](t)(confInboundApply(segment("headerHex", "header", `{"alg":"ES256","typ":"JWT"}`), spec["headerSegment"]))
	p := confInboundMust[string](t)(confInboundApply(segment("payloadHex", "payload", ""), spec["payloadSegment"]))
	keyRef := any(defaultKey)
	if k, ok := spec["key"]; ok {
		keyRef = k
	}
	priv := r.privKey(t, keyRef)
	transforms, _ := spec["signature"].([]any)
	for i := 0; ; i++ {
		s, err := confInboundApply(confInboundSign(t, priv, []byte(h+"."+p)), spec["signature"])
		if err != nil && i < 63 && slices.Contains(transforms, any("std-alphabet")) {
			continue // a signature with neither '-' nor '_': sign again
		}
		if err != nil {
			t.Fatal(err)
		}
		return confInboundMust[string](t)(confInboundApply(h+"."+p+"."+s, spec["transform"]))
	}
}

const confInboundAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func confInboundApply(text string, list any) (string, error) {
	transforms, _ := list.([]any)
	for _, tr := range transforms {
		out, err := confInboundTransform(text, tr)
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

func confInboundTransform(text string, tr any) (string, error) {
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
		i := strings.IndexByte(confInboundAlphabet, text[len(text)-1])
		if i < 0 || i == 63 {
			return "", fmt.Errorf("trailing-bits on %q", text)
		}
		return text[:len(text)-1] + confInboundAlphabet[i+1:i+2], nil
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
	confInboundPlaceholder = regexp.MustCompile(`\$\{([^}]*)\}`)
	confInboundWhole       = regexp.MustCompile(`^\$\{([^}]*)\}$`)
	confInboundTimeExpr    = regexp.MustCompile(`^now(Ms)?(?:([+-])(\d+))?$`)
)

func (r *confInboundRunner) expandText(t *testing.T, text string, ctx *confInboundCtx) []byte {
	out, last := []byte{}, 0
	for _, m := range confInboundPlaceholder.FindAllStringSubmatchIndex(text, -1) {
		out = append(out, text[last:m[0]]...)
		expr := text[m[2]:m[3]]
		if h, ok := strings.CutPrefix(expr, "hex:"); ok {
			out = append(out, confInboundMust[[]byte](t)(hex.DecodeString(h))...)
		} else {
			switch v := r.resolve(t, expr, ctx).(type) {
			case confInboundTime:
				out = strconv.AppendInt(out, v.v, 10)
			case string:
				out = append(out, v...)
			}
		}
		last = m[1]
	}
	return append(out, text[last:]...)
}

func (r *confInboundRunner) resolve(t *testing.T, expr string, ctx *confInboundCtx) any {
	if m := confInboundTimeExpr.FindStringSubmatch(expr); m != nil {
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
		return confInboundTime{v, slack}
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
		return confInboundEscape(ctx.token)
	case "$":
		return "$"
	}
	t.Fatalf("unknown placeholder ${%s}", expr)
	return nil
}

// confInboundEscape escapes ", \ and C0 controls, and nothing else.
func confInboundEscape(s string) string {
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

func (r *confInboundRunner) expandWant(t *testing.T, v any, ctx *confInboundCtx) any {
	switch v := v.(type) {
	case string:
		if m := confInboundWhole.FindStringSubmatch(v); m != nil {
			return r.resolve(t, m[1], ctx)
		}
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = r.expandWant(t, x, ctx)
		}
		return out
	case map[string]any:
		if n, ok := v["$number"].(string); ok && len(v) == 1 {
			return map[string]float64{"NaN": math.NaN(), "Infinity": math.Inf(1), "-Infinity": math.Inf(-1), "-0": math.Copysign(0, -1)}[n]
		}
		if s, ok := v["$illFormed"].(string); ok && len(v) == 1 {
			return s + "\xff"
		}
		out := make(map[string]any, len(v))
		for k, x := range v {
			out[k] = r.expandWant(t, x, ctx)
		}
		return out
	}
	return v
}

// --- comparison ------------------------------------------------------------------------------------------------------

// confInboundMatch compares got with want as FORMAT.md 5.3 says; exact also refuses members want does not list.
func confInboundMatch(got, want any, path string, exact bool) error {
	switch w := want.(type) {
	case confInboundTime:
		g, ok := got.(float64)
		if !ok || g != math.Trunc(g) || int64(g) < w.v || int64(g) > w.v+w.slack {
			return fmt.Errorf("%s: got %s, want %d..%d", path, confInboundJSON(got), w.v, w.v+w.slack)
		}
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return fmt.Errorf("%s: got %s, want %s", path, confInboundJSON(got), confInboundJSON(want))
		}
		for i := range w {
			if err := confInboundMatch(g[i], w[i], fmt.Sprintf("%s[%d]", path, i), exact); err != nil {
				return err
			}
		}
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok || (exact && len(g) != len(w)) {
			return fmt.Errorf("%s: got %s, want %s", path, confInboundJSON(got), confInboundJSON(want))
		}
		for k, wv := range w {
			gv, present := g[k]
			if !present {
				return fmt.Errorf("%s.%s: missing", path, k)
			}
			if err := confInboundMatch(gv, wv, path+"."+k, exact); err != nil {
				return err
			}
		}
	case float64:
		if g, ok := got.(float64); !ok || g != w {
			return fmt.Errorf("%s: got %v, want %v", path, got, want)
		}
	default:
		if got != want {
			return fmt.Errorf("%s: got %s, want %s", path, confInboundJSON(got), confInboundJSON(want))
		}
	}
	return nil
}

func confInboundOnly(t *testing.T, want map[string]any, allowed ...string) {
	for k := range want {
		if !slices.Contains(allowed, k) {
			t.Fatalf("want member %q is not supported by this runner", k)
		}
	}
}

func confInboundJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
