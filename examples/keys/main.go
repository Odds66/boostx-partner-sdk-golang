package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx"
	boostxtokens "github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

func main() {
	// Generate test keys (in production, load from secure storage)
	partnerPrivateKey, partnerPublicKey := generateTestKeyPair("Partner")
	boostxPrivateKey, boostxPublicKey := generateTestKeyPair("BoostX")

	// === PARTNER SIDE: Create GamePass ===
	fmt.Println("=== Creating GamePass (Partner -> BoostX) ===")

	gamePassToken, err := boostx.CreateGamePassToken(partnerPrivateKey, boostx.GamePassParams{
		Partner:    "partner-123",
		User:       "user-456",
		Bet:        "bet-789",
		Amount:     100.0,
		Currency:   "USD",
		X:          2.0,
		XMin:       1.1,
		XMax:       10.0,
		EventTitle: "Real Madrid vs Barcelona — Match Winner: Real Madrid",
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

	// === BOOSTX SIDE: Create Booster response (simulated) ===
	fmt.Println("=== Creating Booster Response (BoostX -> Partner) ===")

	boosterToken := createSimulatedBoosterToken(boostxPrivateKey, partnerPrivateKey, 1.5, 3, true, false)
	fmt.Printf("Booster Token:\n%s\n\n", boosterToken)

	// === PARTNER SIDE: Validate Booster and calculate final coefficient ===
	fmt.Println("=== Validating Booster (Partner Side) ===")

	result, err := boostxtokens.ParseBoosterToken(boosterToken, boostxPublicKey, partnerPublicKey)
	if err != nil {
		log.Fatalf("Failed to parse Booster: %v", err)
	}

	fmt.Printf("Booster Result:\n")
	fmt.Printf("  Round: %d\n", result.Round)
	fmt.Printf("  Boost: %.2f\n", result.Boost)
	fmt.Printf("  Final: %v\n", result.Final)
	fmt.Printf("  Jackpot: %v\n\n", result.Jackpot)

	fmt.Printf("GID (from Booster):\n")
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

	// === Settlement example ===
	fmt.Println("\n=== Creating Settlement (Partner -> BoostX) ===")

	settlementToken, err := boostx.CreateSettlementToken(partnerPrivateKey, boostx.SettlementParams{
		Partner:  "partner-123",
		User:     "user-456",
		Bet:      "bet-789",
		Result:   "won",
		Amount:   150.0,
		Currency: "USD",
	})
	if err != nil {
		log.Fatalf("Failed to create Settlement: %v", err)
	}
	fmt.Printf("Settlement Token:\n%s\n", settlementToken)
}

func generateTestKeyPair(name string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate %s key pair: %v", name, err)
	}
	fmt.Printf("Generated %s test key pair (P-256)\n", name)
	return privateKey, &privateKey.PublicKey
}

// createSimulatedBoosterToken creates a Booster token as BoostX would.
// This is for demonstration purposes only.
func createSimulatedBoosterToken(
	boostxPrivateKey *ecdsa.PrivateKey,
	partnerPrivateKey *ecdsa.PrivateKey,
	boost float64,
	round int,
	final bool,
	jackpot bool,
) string {
	// Build GID (as partner would)
	gid, err := boostxtokens.BuildGID("partner-123", "user-456", "bet-789", partnerPrivateKey)
	if err != nil {
		log.Fatalf("Failed to build GID: %v", err)
	}

	// Create booster claims with nested structure
	type boosterPayload struct {
		GID     boostxtokens.GID `json:"gid"`
		Round   int              `json:"round"`
		Boost   float64          `json:"boost"`
		Final   bool             `json:"final"`
		Jackpot bool             `json:"jackpot"`
	}
	claims := struct {
		Booster boosterPayload `json:"booster"`
		boostxtokens.RegisteredClaims
	}{
		Booster: boosterPayload{
			GID:     *gid,
			Round:   round,
			Boost:   boost,
			Final:   final,
			Jackpot: jackpot,
		},
	}

	tokenString, err := boostxtokens.SignJWT(claims, boostxPrivateKey)
	if err != nil {
		log.Fatalf("Failed to create simulated Booster token: %v", err)
	}
	return tokenString
}
