package tokens

import (
	"errors"
	"testing"
)

func TestBuildAndVerifyGID(t *testing.T) {
	privateKey, publicKey := generateTestKey(t)

	gid, err := BuildGID("partner-123", "user-456", "bet-789", privateKey)
	if err != nil {
		t.Fatalf("BuildGID failed: %v", err)
	}

	if gid.Partner != "partner-123" {
		t.Errorf("expected partner=%q, got %q", "partner-123", gid.Partner)
	}
	if gid.User != "user-456" {
		t.Errorf("expected user=%q, got %q", "user-456", gid.User)
	}
	if gid.Bet != "bet-789" {
		t.Errorf("expected bet=%q, got %q", "bet-789", gid.Bet)
	}
	if gid.Signature == "" {
		t.Error("expected non-empty signature")
	}

	if err := VerifyGID(gid, publicKey); err != nil {
		t.Fatalf("VerifyGID failed: %v", err)
	}
}

func TestVerifyGID_TamperedField(t *testing.T) {
	privateKey, publicKey := generateTestKey(t)

	gid, _ := BuildGID("partner", "user", "bet", privateKey)

	// Tamper with the bet field after signing
	gid.Bet = "tampered-bet"

	err := VerifyGID(gid, publicKey)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for tampered GID, got %v", err)
	}
}

func TestVerifyGID_WrongKey(t *testing.T) {
	privateKey, _ := generateTestKey(t)
	_, wrongPublicKey := generateTestKey(t)

	gid, _ := BuildGID("partner", "user", "bet", privateKey)

	err := VerifyGID(gid, wrongPublicKey)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestBuildGID_NilPrivateKey(t *testing.T) {
	_, err := BuildGID("partner", "user", "bet", nil)
	if !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestBuildGID_MissingClaims(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	testCases := []struct {
		name    string
		partner string
		user    string
		bet     string
	}{
		{"missing partner", "", "user", "bet"},
		{"missing user", "partner", "", "bet"},
		{"missing bet", "partner", "user", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildGID(tc.partner, tc.user, tc.bet, privateKey)
			if !errors.Is(err, ErrMissingClaim) {
				t.Errorf("expected ErrMissingClaim, got %v", err)
			}
		})
	}
}

func TestVerifyGID_NilPublicKey(t *testing.T) {
	privateKey, _ := generateTestKey(t)

	gid, _ := BuildGID("partner", "user", "bet", privateKey)

	err := VerifyGID(gid, nil)
	if !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("expected ErrInvalidPublicKey, got %v", err)
	}
}

func TestVerifyGID_NilGID(t *testing.T) {
	_, publicKey := generateTestKey(t)

	err := VerifyGID(nil, publicKey)
	if !errors.Is(err, ErrInvalidGID) {
		t.Errorf("expected ErrInvalidGID, got %v", err)
	}
}
