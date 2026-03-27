package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
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

func TestNewStaticPublicKeyStore(t *testing.T) {
	_, partnerPubKey := generateTestKeyPair(t)
	_, boostxPubKey := generateTestKeyPair(t)

	store, err := NewStaticPublicKeyStore(partnerPubKey, boostxPubKey)
	if err != nil {
		t.Fatalf("NewStaticPublicKeyStore failed: %v", err)
	}

	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestNewStaticPublicKeyStore_NilPartnerKey(t *testing.T) {
	_, boostxPubKey := generateTestKeyPair(t)

	_, err := NewStaticPublicKeyStore(nil, boostxPubKey)
	if err == nil {
		t.Error("expected error for nil partnerKey")
	}
}

func TestNewStaticPublicKeyStore_NilBoostxKey(t *testing.T) {
	_, partnerPubKey := generateTestKeyPair(t)

	_, err := NewStaticPublicKeyStore(partnerPubKey, nil)
	if err == nil {
		t.Error("expected error for nil boostxKey")
	}
}

func TestStaticPublicKeyStore_PartnerPublicKey(t *testing.T) {
	_, partnerPubKey := generateTestKeyPair(t)
	_, boostxPubKey := generateTestKeyPair(t)

	store, _ := NewStaticPublicKeyStore(partnerPubKey, boostxPubKey)

	ctx := t.Context()
	key, err := store.PartnerPublicKey(ctx, "partner", "user", "bet")
	if err != nil {
		t.Fatalf("PartnerPublicKey failed: %v", err)
	}

	if key != partnerPubKey {
		t.Error("returned key does not match expected key")
	}
}

func TestStaticPublicKeyStore_BoostxPublicKey(t *testing.T) {
	_, partnerPubKey := generateTestKeyPair(t)
	_, boostxPubKey := generateTestKeyPair(t)

	store, _ := NewStaticPublicKeyStore(partnerPubKey, boostxPubKey)

	ctx := t.Context()
	key, err := store.BoostxPublicKey(ctx, "partner", "user", "bet")
	if err != nil {
		t.Fatalf("BoostxPublicKey failed: %v", err)
	}

	if key != boostxPubKey {
		t.Error("returned key does not match expected key")
	}
}

func TestLoadFromFiles(t *testing.T) {
	_, partnerPubKey := generateTestKeyPair(t)
	_, boostxPubKey := generateTestKeyPair(t)

	tmpDir := t.TempDir()

	// Write partner public key
	partnerPubBytes, _ := x509.MarshalPKIXPublicKey(partnerPubKey)
	partnerPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: partnerPubBytes})
	partnerPath := filepath.Join(tmpDir, "partner.pem")
	if err := os.WriteFile(partnerPath, partnerPEM, 0644); err != nil {
		t.Fatalf("failed to write partner key: %v", err)
	}

	// Write Boostx public key
	boostxPubBytes, _ := x509.MarshalPKIXPublicKey(boostxPubKey)
	boostxPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: boostxPubBytes})
	boostxPath := filepath.Join(tmpDir, "boostx.pem")
	if err := os.WriteFile(boostxPath, boostxPEM, 0644); err != nil {
		t.Fatalf("failed to write boostx key: %v", err)
	}

	store, err := LoadFromFiles(partnerPath, boostxPath)
	if err != nil {
		t.Fatalf("LoadFromFiles failed: %v", err)
	}

	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestLoadFromFiles_PartnerNotFound(t *testing.T) {
	_, boostxPubKey := generateTestKeyPair(t)

	tmpDir := t.TempDir()

	boostxPubBytes, _ := x509.MarshalPKIXPublicKey(boostxPubKey)
	boostxPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: boostxPubBytes})
	boostxPath := filepath.Join(tmpDir, "boostx.pem")
	os.WriteFile(boostxPath, boostxPEM, 0644)

	_, err := LoadFromFiles("/nonexistent/partner.pem", boostxPath)
	if err == nil {
		t.Error("expected error for missing partner file")
	}
}

func TestLoadFromPEM(t *testing.T) {
	_, partnerPubKey := generateTestKeyPair(t)
	_, boostxPubKey := generateTestKeyPair(t)

	partnerPubBytes, _ := x509.MarshalPKIXPublicKey(partnerPubKey)
	partnerPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: partnerPubBytes})

	boostxPubBytes, _ := x509.MarshalPKIXPublicKey(boostxPubKey)
	boostxPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: boostxPubBytes})

	store, err := LoadFromPEM(partnerPEM, boostxPEM)
	if err != nil {
		t.Fatalf("LoadFromPEM failed: %v", err)
	}

	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestLoadFromPEM_InvalidPartnerPEM(t *testing.T) {
	_, boostxPubKey := generateTestKeyPair(t)

	boostxPubBytes, _ := x509.MarshalPKIXPublicKey(boostxPubKey)
	boostxPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: boostxPubBytes})

	_, err := LoadFromPEM([]byte("invalid pem"), boostxPEM)
	if err == nil {
		t.Error("expected error for invalid partner PEM")
	}
}

func TestLoadFromPEM_InvalidBoostxPEM(t *testing.T) {
	_, partnerPubKey := generateTestKeyPair(t)

	partnerPubBytes, _ := x509.MarshalPKIXPublicKey(partnerPubKey)
	partnerPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: partnerPubBytes})

	_, err := LoadFromPEM(partnerPEM, []byte("invalid pem"))
	if err == nil {
		t.Error("expected error for invalid boostx PEM")
	}
}
