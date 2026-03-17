package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx"
	boostxtokens "github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

func main() {
	// Generate test keys (in production, load from secure storage)
	partnerPrivateKey, partnerPublicKey := generateTestKeyPair("Partner")
	boostXPrivateKey, boostXPublicKey := generateTestKeyPair("BoostX")

	// === PARTNER SIDE: Create GamePass ===
	fmt.Println("=== Creating GamePass (Partner -> BoostX) ===")

	gamePassToken, err := boostx.CreateGamePassToken(partnerPrivateKey, boostx.GamePassParams{
		Partner:        "partner-123",
		User:           "user-456",
		Bet:            "bet-789",
		Amount:         100.0,
		Currency:       "USD",
		X:              2.0,
		XMin:           1.1,
		XMax:           10.0,
		EventName:      "Real Madrid vs Barcelona",
		EventMarket:    "Match Winner",
		EventSelection: "Real Madrid",
	})
	if err != nil {
		log.Fatalf("Failed to create GamePass: %v", err)
	}

	fmt.Printf("GamePass Token:\n%s\n\n", gamePassToken)

	// Verify the GamePass can be parsed
	parsedGamePass, err := boostxtokens.ParseGamePassToken(gamePassToken, partnerPublicKey)
	if err != nil {
		log.Fatalf("Failed to parse GamePass: %v", err)
	}
	fmt.Printf("Parsed GamePass Claims:\n")
	fmt.Printf("  Partner: %s\n", parsedGamePass.Partner)
	fmt.Printf("  User: %s\n", parsedGamePass.User)
	fmt.Printf("  Bet: %s\n", parsedGamePass.Bet)
	fmt.Printf("  Amount: %.2f %s\n", parsedGamePass.Amount, parsedGamePass.Currency)
	fmt.Printf("  X: %.2f (min: %.2f, max: %.2f)\n\n", parsedGamePass.X, parsedGamePass.XMin, parsedGamePass.XMax)

	// === BOOSTX SIDE: Create Boost response (simulated) ===
	fmt.Println("=== Creating Boost Response (BoostX -> Partner) ===")

	boostToken := createSimulatedBoostToken(boostXPrivateKey, partnerPrivateKey, 1.5, 3, true, false)
	fmt.Printf("Boost Token:\n%s\n\n", boostToken)

	// === PARTNER SIDE: Validate Boost and calculate final coefficient ===
	fmt.Println("=== Validating Boost (Partner Side) ===")

	result, err := boostxtokens.ParseBoostToken(boostToken, boostXPublicKey, partnerPublicKey)
	if err != nil {
		log.Fatalf("Failed to parse Boost: %v", err)
	}

	fmt.Printf("Boost Result:\n")
	fmt.Printf("  Round: %d\n", result.Round)
	fmt.Printf("  Boost: %.2f\n", result.Boost)
	fmt.Printf("  Final: %v\n", result.Final)
	fmt.Printf("  Jackpot: %v\n\n", result.Jackpot)

	fmt.Printf("Identity (from Boost):\n")
	fmt.Printf("  Partner: %s\n", result.Partner)
	fmt.Printf("  User: %s\n", result.User)
	fmt.Printf("  Bet: %s\n\n", result.Bet)

	// Partner looks up X from own DB using bet ID, then calculates coefficient
	originalX := 2.0 // Would come from partner's DB
	finalCoefficient := boostxtokens.CalculateFinalCoefficient(originalX, result.Boost)
	fmt.Printf("Final Coefficient Calculation:\n")
	fmt.Printf("  Formula: X' = 1 + (X - 1) * boost\n")
	fmt.Printf("  X' = 1 + (%.2f - 1) * %.2f = %.2f\n\n",
		originalX, result.Boost, finalCoefficient)

	// Demonstrate coefficient calculation directly
	fmt.Println("=== Coefficient Calculation Examples ===")
	examples := []struct{ x, boost float64 }{
		{2.0, 1.0}, // No boost
		{2.0, 1.5}, // 50% boost
		{2.0, 2.0}, // 100% boost
		{3.0, 1.5}, // Different X
	}
	for _, ex := range examples {
		final := boostxtokens.CalculateFinalCoefficient(ex.x, ex.boost)
		fmt.Printf("  X=%.1f, Boost=%.1f -> Final=%.2f\n", ex.x, ex.boost, final)
	}
}

func generateTestKeyPair(name string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate %s key pair: %v", name, err)
	}
	fmt.Printf("Generated %s test key pair (P-256)\n", name)
	return privateKey, &privateKey.PublicKey
}

// simulatedBoostClaims is used to create test Boost tokens.
type simulatedBoostClaims struct {
	Identity string  `json:"identity"`
	Round    int     `json:"round"`
	Boost    float64 `json:"boost"`
	Final    bool    `json:"final"`
	Jackpot  bool    `json:"jackpot"`
	IssuedAt int64   `json:"iat,omitempty"`
}

// createSimulatedBoostToken creates a Boost token as BoostX would.
// This is for demonstration purposes only.
func createSimulatedBoostToken(
	boostXPrivateKey *ecdsa.PrivateKey,
	partnerPrivateKey *ecdsa.PrivateKey,
	boost float64,
	round int,
	final bool,
	jackpot bool,
) string {
	// Create identity sub-token (as partner would)
	identityClaims := struct {
		Partner string `json:"partner"`
		User    string `json:"user"`
		Bet     string `json:"bet"`
	}{
		Partner: "partner-123",
		User:    "user-456",
		Bet:     "bet-789",
	}
	identityJWT, err := signJWT(identityClaims, partnerPrivateKey)
	if err != nil {
		log.Fatalf("Failed to create identity token: %v", err)
	}

	claims := simulatedBoostClaims{
		Identity: identityJWT,
		Round:    round,
		Boost:    boost,
		Final:    final,
		Jackpot:  jackpot,
		IssuedAt: time.Now().Unix(),
	}

	tokenString, err := signJWT(claims, boostXPrivateKey)
	if err != nil {
		log.Fatalf("Failed to create simulated Boost token: %v", err)
	}
	return tokenString
}

// signJWT creates a signed JWT token using ES256 (for test purposes only).
func signJWT(claims any, privateKey *ecdsa.PrivateKey) (string, error) {
	header := struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{Alg: "ES256", Typ: "JWT"}

	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadJSON, _ := json.Marshal(claims)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", err
	}

	signature := make([]byte, 64)
	rBytes, sBytes := r.Bytes(), s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
