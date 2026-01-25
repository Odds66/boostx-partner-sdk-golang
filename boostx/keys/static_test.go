package keys

import (
	"context"
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

func TestNewStaticKeyStore(t *testing.T) {
	_, gamepassPubKey := generateTestKeyPair(t)
	_, boostPubKey := generateTestKeyPair(t)

	store, err := NewStaticKeyStore(gamepassPubKey, boostPubKey)
	if err != nil {
		t.Fatalf("NewStaticKeyStore failed: %v", err)
	}

	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestNewStaticKeyStore_NilGamepassKey(t *testing.T) {
	_, boostPubKey := generateTestKeyPair(t)

	_, err := NewStaticKeyStore(nil, boostPubKey)
	if err == nil {
		t.Error("expected error for nil gamepassKey")
	}
}

func TestNewStaticKeyStore_NilBoostKey(t *testing.T) {
	_, gamepassPubKey := generateTestKeyPair(t)

	_, err := NewStaticKeyStore(gamepassPubKey, nil)
	if err == nil {
		t.Error("expected error for nil boostKey")
	}
}

func TestStaticKeyStore_GamePassPublicKey(t *testing.T) {
	_, gamepassPubKey := generateTestKeyPair(t)
	_, boostPubKey := generateTestKeyPair(t)

	store, _ := NewStaticKeyStore(gamepassPubKey, boostPubKey)

	ctx := context.Background()
	key, err := store.GamePassPublicKey(ctx, "partner", "user", "bet")
	if err != nil {
		t.Fatalf("GamePassPublicKey failed: %v", err)
	}

	if key != gamepassPubKey {
		t.Error("returned key does not match expected key")
	}
}

func TestStaticKeyStore_BoostPublicKey(t *testing.T) {
	_, gamepassPubKey := generateTestKeyPair(t)
	_, boostPubKey := generateTestKeyPair(t)

	store, _ := NewStaticKeyStore(gamepassPubKey, boostPubKey)

	ctx := context.Background()
	key, err := store.BoostPublicKey(ctx, "partner", "user", "bet")
	if err != nil {
		t.Fatalf("BoostPublicKey failed: %v", err)
	}

	if key != boostPubKey {
		t.Error("returned key does not match expected key")
	}
}

func TestLoadFromFiles(t *testing.T) {
	_, gamepassPubKey := generateTestKeyPair(t)
	_, boostPubKey := generateTestKeyPair(t)

	tmpDir := t.TempDir()

	// Write gamepass public key
	gamepassPubBytes, _ := x509.MarshalPKIXPublicKey(gamepassPubKey)
	gamepassPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: gamepassPubBytes})
	gamepassPath := filepath.Join(tmpDir, "gamepass.pem")
	if err := os.WriteFile(gamepassPath, gamepassPEM, 0644); err != nil {
		t.Fatalf("failed to write gamepass key: %v", err)
	}

	// Write boost public key
	boostPubBytes, _ := x509.MarshalPKIXPublicKey(boostPubKey)
	boostPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: boostPubBytes})
	boostPath := filepath.Join(tmpDir, "boost.pem")
	if err := os.WriteFile(boostPath, boostPEM, 0644); err != nil {
		t.Fatalf("failed to write boost key: %v", err)
	}

	store, err := LoadFromFiles(gamepassPath, boostPath)
	if err != nil {
		t.Fatalf("LoadFromFiles failed: %v", err)
	}

	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestLoadFromFiles_GamepassNotFound(t *testing.T) {
	_, boostPubKey := generateTestKeyPair(t)

	tmpDir := t.TempDir()

	boostPubBytes, _ := x509.MarshalPKIXPublicKey(boostPubKey)
	boostPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: boostPubBytes})
	boostPath := filepath.Join(tmpDir, "boost.pem")
	os.WriteFile(boostPath, boostPEM, 0644)

	_, err := LoadFromFiles("/nonexistent/gamepass.pem", boostPath)
	if err == nil {
		t.Error("expected error for missing gamepass file")
	}
}

func TestLoadFromPEM(t *testing.T) {
	_, gamepassPubKey := generateTestKeyPair(t)
	_, boostPubKey := generateTestKeyPair(t)

	gamepassPubBytes, _ := x509.MarshalPKIXPublicKey(gamepassPubKey)
	gamepassPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: gamepassPubBytes})

	boostPubBytes, _ := x509.MarshalPKIXPublicKey(boostPubKey)
	boostPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: boostPubBytes})

	store, err := LoadFromPEM(gamepassPEM, boostPEM)
	if err != nil {
		t.Fatalf("LoadFromPEM failed: %v", err)
	}

	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestLoadFromPEM_InvalidGamepassPEM(t *testing.T) {
	_, boostPubKey := generateTestKeyPair(t)

	boostPubBytes, _ := x509.MarshalPKIXPublicKey(boostPubKey)
	boostPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: boostPubBytes})

	_, err := LoadFromPEM([]byte("invalid pem"), boostPEM)
	if err == nil {
		t.Error("expected error for invalid gamepass PEM")
	}
}

func TestLoadFromPEM_InvalidBoostPEM(t *testing.T) {
	_, gamepassPubKey := generateTestKeyPair(t)

	gamepassPubBytes, _ := x509.MarshalPKIXPublicKey(gamepassPubKey)
	gamepassPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: gamepassPubBytes})

	_, err := LoadFromPEM(gamepassPEM, []byte("invalid pem"))
	if err == nil {
		t.Error("expected error for invalid boost PEM")
	}
}
