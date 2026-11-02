package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

func generateTestKeyPair(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

func TestMemoryKeyStore_RegisterAndLookup(t *testing.T) {
	store := NewMemoryKeyStore()

	aPriv, aPub := generateTestKeyPair(t)
	_, aBoostx := generateTestKeyPair(t)
	bPriv, bPub := generateTestKeyPair(t)
	_, bBoostx := generateTestKeyPair(t)

	if err := store.Register("partner-a", aPub, aPriv, aBoostx); err != nil {
		t.Fatalf("Register a: %v", err)
	}
	if err := store.Register("partner-b", bPub, bPriv, bBoostx); err != nil {
		t.Fatalf("Register b: %v", err)
	}

	ctx := context.Background()
	if got, _ := store.PartnerPublicKey(ctx, "partner-a"); got != aPub {
		t.Error("partner-a: wrong partner public key")
	}
	if got, _ := store.BoostxPublicKey(ctx, "partner-b"); got != bBoostx {
		t.Error("partner-b: wrong boostx public key")
	}
	if got, _ := store.PartnerPrivateKey(ctx, "partner-b"); got != bPriv {
		t.Error("partner-b: wrong partner private key")
	}

	if _, err := store.PartnerPublicKey(ctx, "nope"); err == nil {
		t.Error("expected error for unknown partner")
	}
}

// TestMemoryKeyStore_PartialKeys checks that a partner registered with only some
// keys errors on the absent ones (e.g. a sign-only store has no public keys).
func TestMemoryKeyStore_PartialKeys(t *testing.T) {
	store := NewMemoryKeyStore()
	priv, _ := generateTestKeyPair(t)
	if err := store.Register("p", nil, priv, nil); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if got, err := store.PartnerPrivateKey(ctx, "p"); err != nil || got != priv {
		t.Errorf("PartnerPrivateKey: got %v, err %v", got, err)
	}
	if _, err := store.PartnerPublicKey(ctx, "p"); !errors.Is(err, tokens.ErrInvalidPublicKey) || errors.Is(err, ErrUnknownPartner) {
		t.Errorf("absent partner public key: expected ErrInvalidPublicKey, got %v", err)
	}
	if _, err := store.BoostxPublicKey(ctx, "p"); !errors.Is(err, tokens.ErrInvalidPublicKey) || errors.Is(err, ErrUnknownPartner) {
		t.Errorf("absent boostx public key: expected ErrInvalidPublicKey, got %v", err)
	}

	_, pub := generateTestKeyPair(t)
	if err := store.Register("q", pub, nil, pub); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PartnerPrivateKey(ctx, "q"); !errors.Is(err, tokens.ErrInvalidPrivateKey) || errors.Is(err, ErrUnknownPartner) {
		t.Errorf("absent partner private key: expected ErrInvalidPrivateKey, got %v", err)
	}
	if _, err := store.PartnerPrivateKey(ctx, "nope"); !errors.Is(err, ErrUnknownPartner) {
		t.Errorf("unknown partner: expected ErrUnknownPartner, got %v", err)
	}
}

func TestMemoryKeyStore_RegisterEmptyPartner(t *testing.T) {
	_, pub := generateTestKeyPair(t)
	store := NewMemoryKeyStore()
	if err := store.Register("", nil, nil, nil); !errors.Is(err, tokens.ErrMissingClaim) {
		t.Errorf("Register: expected ErrMissingClaim, got %v", err)
	}
	if err := store.RegisterWithPartnerPublicKeys("", []*ecdsa.PublicKey{pub}, nil, nil); !errors.Is(err, tokens.ErrMissingClaim) {
		t.Errorf("RegisterWithPartnerPublicKeys: expected ErrMissingClaim, got %v", err)
	}
}

// TestMemoryKeyStore_RegisterRefusesUnusableKeys pins that registration checks
// every key it is given against its role, refuses with the role's key error,
// and keeps the earlier registration.
func TestMemoryKeyStore_RegisterRefusesUnusableKeys(t *testing.T) {
	ctx := context.Background()
	priv, pub := generateTestKeyPair(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	badPubs := map[string]*ecdsa.PublicKey{
		"P-384":      &p384.PublicKey,
		"X nil":      {Curve: elliptic.P256(), Y: pub.Y},
		"off curve":  {Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)},
		"zero value": {},
	}
	badPrivs := map[string]*ecdsa.PrivateKey{
		"P-384":      p384,
		"D nil":      {PublicKey: *pub},
		"D zero":     {PublicKey: *pub, D: big.NewInt(0)},
		"zero value": {},
	}

	store := NewMemoryKeyStore()
	if err := store.Register("p", pub, priv, pub); err != nil {
		t.Fatal(err)
	}
	kept := func(name string) {
		t.Helper()
		if got, err := store.PartnerPublicKeys(ctx, "p"); err != nil || !slices.Equal(got, []*ecdsa.PublicKey{pub}) {
			t.Errorf("%s: the earlier registration was not kept: %v, %v", name, got, err)
		}
		if got, err := store.PartnerPrivateKey(ctx, "p"); err != nil || got != priv {
			t.Errorf("%s: the earlier private key was not kept: %v", name, err)
		}
	}
	for name, bad := range badPubs {
		for role, err := range map[string]error{
			"partner public key": store.Register("p", bad, priv, pub),
			"partner key list":   store.RegisterWithPartnerPublicKeys("p", []*ecdsa.PublicKey{pub, bad}, priv, pub),
			"boostx public key":  store.Register("p", pub, priv, bad),
		} {
			if !errors.Is(err, tokens.ErrInvalidPublicKey) {
				t.Errorf("%s %s: expected ErrInvalidPublicKey, got %v", name, role, err)
			}
		}
		kept(name)
	}
	for name, bad := range badPrivs {
		if err := store.Register("p", pub, bad, pub); !errors.Is(err, tokens.ErrInvalidPrivateKey) {
			t.Errorf("%s partner private key: expected ErrInvalidPrivateKey, got %v", name, err)
		}
		kept(name)
	}
	for name, list := range map[string][]*ecdsa.PublicKey{"nil list": nil, "empty list": {}, "nil entry": {pub, nil}} {
		if err := store.RegisterWithPartnerPublicKeys("p", list, priv, pub); !errors.Is(err, tokens.ErrInvalidPublicKey) {
			t.Errorf("%s: expected ErrInvalidPublicKey, got %v", name, err)
		}
		kept(name)
	}

	// A nil key passed to Register leaves that role out.
	if err := store.Register("p", nil, priv, nil); err != nil {
		t.Errorf("Register with nil public keys: %v", err)
	}

	// Roles are checked in parameter order: partner public keys, partner
	// private key, BoostX public key.
	if err := store.Register("p", badPubs["P-384"], badPrivs["P-384"], badPubs["P-384"]); !errors.Is(err, tokens.ErrInvalidPublicKey) {
		t.Errorf("all three unusable: expected the partner public key's ErrInvalidPublicKey, got %v", err)
	}
	if err := store.Register("p", pub, badPrivs["P-384"], badPubs["P-384"]); !errors.Is(err, tokens.ErrInvalidPrivateKey) {
		t.Errorf("private and boostx keys unusable: expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestMemoryKeyStore_RegisterOverwrite(t *testing.T) {
	store := NewMemoryKeyStore()
	_, pub1 := generateTestKeyPair(t)
	_, pub2 := generateTestKeyPair(t)

	_ = store.Register("p", pub1, nil, nil)
	_ = store.Register("p", pub2, nil, nil) // rotation

	if got, _ := store.PartnerPublicKey(context.Background(), "p"); got != pub2 {
		t.Error("expected the rotated key")
	}
}

// TestMemoryKeyStore_Concurrent runs registers and lookups in parallel; run with
// -race to exercise the RWMutex.
func TestMemoryKeyStore_Concurrent(t *testing.T) {
	store := NewMemoryKeyStore()
	_, pub := generateTestKeyPair(t)
	if err := store.Register("p", pub, nil, nil); err != nil {
		t.Fatal(err)
	}

	pubs := []*ecdsa.PublicKey{pub, pub}
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(4)
		go func() { defer wg.Done(); _ = store.Register("p2", pub, nil, nil) }()
		go func() { defer wg.Done(); _ = store.RegisterWithPartnerPublicKeys("p", pubs, nil, nil) }()
		go func() { defer wg.Done(); _, _ = store.PartnerPublicKey(context.Background(), "p") }()
		go func() { defer wg.Done(); _, _ = store.PartnerPublicKeys(context.Background(), "p") }()
	}
	wg.Wait()
}

// TestMemoryKeyStore_PartnerPublicKeys pins the multi-key registration: order
// kept, copies in and out, nil entries refused, and Register replacing the list.
func TestMemoryKeyStore_PartnerPublicKeys(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryKeyStore()
	_, newPub := generateTestKeyPair(t)
	_, oldPub := generateTestKeyPair(t)

	in := []*ecdsa.PublicKey{newPub, oldPub}
	if err := store.RegisterWithPartnerPublicKeys("p", in, nil, nil); err != nil {
		t.Fatal(err)
	}
	in[0] = oldPub // the store keeps its own copy
	got, err := store.PartnerPublicKeys(ctx, "p")
	if err != nil || !slices.Equal(got, []*ecdsa.PublicKey{newPub, oldPub}) {
		t.Fatalf("PartnerPublicKeys: got %v, %v", got, err)
	}
	got[0] = oldPub // and hands out a copy
	if again, _ := store.PartnerPublicKeys(ctx, "p"); again[0] != newPub {
		t.Error("PartnerPublicKeys returned the stored slice, not a copy")
	}
	if current, _ := store.PartnerPublicKey(ctx, "p"); current != newPub {
		t.Error("PartnerPublicKey: expected the first key")
	}

	if err := store.RegisterWithPartnerPublicKeys("p", []*ecdsa.PublicKey{newPub, nil}, nil, nil); err == nil {
		t.Error("expected an error for a nil entry")
	}
	if got, _ := store.PartnerPublicKeys(ctx, "p"); len(got) != 2 {
		t.Errorf("a refused registration changed the keys: %v", got)
	}

	if err := store.Register("p", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PartnerPublicKeys(ctx, "p"); !errors.Is(err, tokens.ErrInvalidPublicKey) || !strings.Contains(err.Error(), "no partner public key") {
		t.Errorf("PartnerPublicKeys with none: expected ErrInvalidPublicKey, got %v", err)
	}
	if _, err := store.PartnerPublicKey(ctx, "p"); !errors.Is(err, tokens.ErrInvalidPublicKey) {
		t.Errorf("PartnerPublicKey with none: expected ErrInvalidPublicKey, got %v", err)
	}

	if _, err := store.PartnerPublicKeys(ctx, "nope"); !errors.Is(err, ErrUnknownPartner) {
		t.Errorf("unknown partner: expected ErrUnknownPartner, got %v", err)
	}

	_ = store.RegisterWithPartnerPublicKeys("p", []*ecdsa.PublicKey{newPub, oldPub}, nil, nil)
	_ = store.Register("p", newPub, nil, nil) // drops oldPub
	if got, _ := store.PartnerPublicKeys(ctx, "p"); !slices.Equal(got, []*ecdsa.PublicKey{newPub}) {
		t.Errorf("Register: expected only the registered key, got %v", got)
	}
}
