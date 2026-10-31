package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
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
	if _, err := store.PartnerPublicKey(ctx, "p"); err == nil {
		t.Error("expected error for absent partner public key")
	}
	if _, err := store.BoostxPublicKey(ctx, "p"); err == nil {
		t.Error("expected error for absent boostx public key")
	}
}

func TestMemoryKeyStore_RegisterEmptyPartner(t *testing.T) {
	if err := NewMemoryKeyStore().Register("", nil, nil, nil); err == nil {
		t.Fatal("expected error for empty partner")
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

	for _, empty := range [][]*ecdsa.PublicKey{nil, {}} {
		if err := store.RegisterWithPartnerPublicKeys("p", empty, nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := store.PartnerPublicKeys(ctx, "p"); err == nil || !strings.Contains(err.Error(), "no partner public key") {
			t.Errorf("PartnerPublicKeys with %v: expected no partner public key, got %v", empty, err)
		}
		if _, err := store.PartnerPublicKey(ctx, "p"); err == nil || !strings.Contains(err.Error(), "no partner public key") {
			t.Errorf("PartnerPublicKey with %v: expected no partner public key, got %v", empty, err)
		}
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
