package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

func generateTestPEMKeys(t *testing.T) (privateKeyPEM, publicKeyPEM []byte, privateKey *ecdsa.PrivateKey) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode private key
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	privateKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	// Encode public key
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	publicKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return privateKeyPEM, publicKeyPEM, privateKey
}

func TestLoadPrivateKeyFromPEM(t *testing.T) {
	privateKeyPEM, _, originalKey := generateTestPEMKeys(t)

	loaded, err := LoadPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromPEM failed: %v", err)
	}

	// Verify it's the same key by comparing public key coordinates
	if loaded.PublicKey.X.Cmp(originalKey.PublicKey.X) != 0 ||
		loaded.PublicKey.Y.Cmp(originalKey.PublicKey.Y) != 0 {
		t.Error("loaded key does not match original")
	}
}

func TestLoadPrivateKeyFromPEM_ECPrivateKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Use EC PRIVATE KEY format
	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal EC private key: %v", err)
	}
	ecPrivateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	loaded, err := LoadPrivateKeyFromPEM(ecPrivateKeyPEM)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromPEM (EC format) failed: %v", err)
	}

	if loaded.PublicKey.X.Cmp(privateKey.PublicKey.X) != 0 {
		t.Error("loaded key does not match original")
	}
}

func TestLoadPrivateKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := LoadPrivateKeyFromPEM([]byte("not a pem"))
	if !errors.Is(err, tokens.ErrInvalidPrivateKey) {
		t.Errorf("expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestLoadPublicKeyFromPEM(t *testing.T) {
	_, publicKeyPEM, originalKey := generateTestPEMKeys(t)

	loaded, err := LoadPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		t.Fatalf("LoadPublicKeyFromPEM failed: %v", err)
	}

	if loaded.X.Cmp(originalKey.PublicKey.X) != 0 ||
		loaded.Y.Cmp(originalKey.PublicKey.Y) != 0 {
		t.Error("loaded key does not match original")
	}
}

func TestLoadPublicKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := LoadPublicKeyFromPEM([]byte("not a pem"))
	if !errors.Is(err, tokens.ErrInvalidPublicKey) {
		t.Errorf("expected ErrInvalidPublicKey, got %v", err)
	}
}

func TestLoadPrivateKeyFromFile(t *testing.T) {
	privateKeyPEM, _, _ := generateTestPEMKeys(t)

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "private.pem")

	if err := os.WriteFile(keyPath, privateKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	loaded, err := LoadPrivateKeyFromFile(keyPath)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromFile failed: %v", err)
	}

	if loaded == nil {
		t.Error("expected non-nil key")
	}
}

func TestLoadPrivateKeyFromFile_NotFound(t *testing.T) {
	_, err := LoadPrivateKeyFromFile("/nonexistent/path/key.pem")
	if !errors.Is(err, tokens.ErrInvalidPrivateKey) {
		t.Errorf("expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestLoadPublicKeyFromFile(t *testing.T) {
	_, publicKeyPEM, _ := generateTestPEMKeys(t)

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "public.pem")

	if err := os.WriteFile(keyPath, publicKeyPEM, 0644); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	loaded, err := LoadPublicKeyFromFile(keyPath)
	if err != nil {
		t.Fatalf("LoadPublicKeyFromFile failed: %v", err)
	}

	if loaded == nil {
		t.Error("expected non-nil key")
	}
}

func TestLoadPublicKeyFromFile_NotFound(t *testing.T) {
	_, err := LoadPublicKeyFromFile("/nonexistent/path/key.pem")
	if !errors.Is(err, tokens.ErrInvalidPublicKey) {
		t.Errorf("expected ErrInvalidPublicKey, got %v", err)
	}
}
