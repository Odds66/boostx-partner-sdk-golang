package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(2)
		go func() { defer wg.Done(); _ = store.Register("p2", pub, nil, nil) }()
		go func() { defer wg.Done(); _, _ = store.PartnerPublicKey(context.Background(), "p") }()
	}
	wg.Wait()
}
