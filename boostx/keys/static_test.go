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
	_, boosterPubKey := generateTestKeyPair(t)

	store, err := NewStaticKeyStore(gamepassPubKey, boosterPubKey)
	if err != nil {
		t.Fatalf("NewStaticKeyStore failed: %v", err)
	}

	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestNewStaticKeyStore_NilGamepassKey(t *testing.T) {
	_, boosterPubKey := generateTestKeyPair(t)

	_, err := NewStaticKeyStore(nil, boosterPubKey)
	if err == nil {
		t.Error("expected error for nil gamepassKey")
	}
}

func TestNewStaticKeyStore_NilBoosterKey(t *testing.T) {
	_, gamepassPubKey := generateTestKeyPair(t)

	_, err := NewStaticKeyStore(gamepassPubKey, nil)
	if err == nil {
		t.Error("expected error for nil boosterKey")
	}
}

func TestStaticKeyStore_GamePassPublicKey(t *testing.T) {
	_, gamepassPubKey := generateTestKeyPair(t)
	_, boosterPubKey := generateTestKeyPair(t)

	store, _ := NewStaticKeyStore(gamepassPubKey, boosterPubKey)

	ctx := context.Background()
	key, err := store.GamePassPublicKey(ctx, "partner", "user", "bet")
	if err != nil {
		t.Fatalf("GamePassPublicKey failed: %v", err)
	}

	if key != gamepassPubKey {
		t.Error("returned key does not match expected key")
	}
}

func TestStaticKeyStore_BoosterPublicKey(t *testing.T) {
	_, gamepassPubKey := generateTestKeyPair(t)
	_, boosterPubKey := generateTestKeyPair(t)

	store, _ := NewStaticKeyStore(gamepassPubKey, boosterPubKey)

	ctx := context.Background()
	key, err := store.BoosterPublicKey(ctx, "partner", "user", "bet")
	if err != nil {
		t.Fatalf("BoosterPublicKey failed: %v", err)
	}

	if key != boosterPubKey {
		t.Error("returned key does not match expected key")
	}
}

func TestLoadFromFiles(t *testing.T) {
	_, gamepassPubKey := generateTestKeyPair(t)
	_, boosterPubKey := generateTestKeyPair(t)

	tmpDir := t.TempDir()

	// Write gamepass public key
	gamepassPubBytes, _ := x509.MarshalPKIXPublicKey(gamepassPubKey)
	gamepassPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: gamepassPubBytes})
	gamepassPath := filepath.Join(tmpDir, "gamepass.pem")
	if err := os.WriteFile(gamepassPath, gamepassPEM, 0644); err != nil {
		t.Fatalf("failed to write gamepass key: %v", err)
	}

	// Write booster public key
	boosterPubBytes, _ := x509.MarshalPKIXPublicKey(boosterPubKey)
	boosterPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: boosterPubBytes})
	boosterPath := filepath.Join(tmpDir, "booster.pem")
	if err := os.WriteFile(boosterPath, boosterPEM, 0644); err != nil {
		t.Fatalf("failed to write booster key: %v", err)
	}

	store, err := LoadFromFiles(gamepassPath, boosterPath)
	if err != nil {
		t.Fatalf("LoadFromFiles failed: %v", err)
	}

	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestLoadFromFiles_GamepassNotFound(t *testing.T) {
	_, boosterPubKey := generateTestKeyPair(t)

	tmpDir := t.TempDir()

	boosterPubBytes, _ := x509.MarshalPKIXPublicKey(boosterPubKey)
	boosterPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: boosterPubBytes})
	boosterPath := filepath.Join(tmpDir, "booster.pem")
	os.WriteFile(boosterPath, boosterPEM, 0644)

	_, err := LoadFromFiles("/nonexistent/gamepass.pem", boosterPath)
	if err == nil {
		t.Error("expected error for missing gamepass file")
	}
}

func TestLoadFromPEM(t *testing.T) {
	_, gamepassPubKey := generateTestKeyPair(t)
	_, boosterPubKey := generateTestKeyPair(t)

	gamepassPubBytes, _ := x509.MarshalPKIXPublicKey(gamepassPubKey)
	gamepassPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: gamepassPubBytes})

	boosterPubBytes, _ := x509.MarshalPKIXPublicKey(boosterPubKey)
	boosterPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: boosterPubBytes})

	store, err := LoadFromPEM(gamepassPEM, boosterPEM)
	if err != nil {
		t.Fatalf("LoadFromPEM failed: %v", err)
	}

	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestLoadFromPEM_InvalidGamepassPEM(t *testing.T) {
	_, boosterPubKey := generateTestKeyPair(t)

	boosterPubBytes, _ := x509.MarshalPKIXPublicKey(boosterPubKey)
	boosterPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: boosterPubBytes})

	_, err := LoadFromPEM([]byte("invalid pem"), boosterPEM)
	if err == nil {
		t.Error("expected error for invalid gamepass PEM")
	}
}

func TestLoadFromPEM_InvalidBoosterPEM(t *testing.T) {
	_, gamepassPubKey := generateTestKeyPair(t)

	gamepassPubBytes, _ := x509.MarshalPKIXPublicKey(gamepassPubKey)
	gamepassPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: gamepassPubBytes})

	_, err := LoadFromPEM(gamepassPEM, []byte("invalid pem"))
	if err == nil {
		t.Error("expected error for invalid booster PEM")
	}
}
