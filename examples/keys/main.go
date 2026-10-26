package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx"
	boostxtokens "github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

func main() {
	// Generate test keys (in production, load from secure storage)
	partnerPrivateKey, partnerPublicKey := generateTestKeyPair("Partner")
	boostxPrivateKey, boostxPublicKey := generateTestKeyPair("BoostX")

	// The bet's xrange.init and xrange.decimals, kept in the partner's DB.
	xBase, decimals := 2.0, 4

	// === PARTNER SIDE: Create GamePass ===
	fmt.Println("=== Creating GamePass (Partner -> BoostX) ===")

	gamePassToken, err := boostx.CreateGamePassToken(partnerPrivateKey, boostx.GamePassParams{
		Partner:    "partner-123",
		User:       "user-456",
		Bet:        "bet-789",
		Amount:     100.0,
		Currency:   "USD",
		X:          xBase,
		XMin:       1.1,
		XMax:       10.0,
		XDecimals:  decimals,
		EventTitle: "Real Madrid vs Barcelona — Match Winner: Real Madrid",
		Demo:       true, // mark this as a demo/test session (optional; omit for real bets)
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
	fmt.Printf("  X: %.2f (min: %.2f, max: %.2f, decimals: %d)\n", parsedGamePass.X, parsedGamePass.XMin, parsedGamePass.XMax, parsedGamePass.XDecimals)
	fmt.Printf("  Demo: %t\n\n", parsedGamePass.Demo)

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

	// The X the player saw, from the bet's xBase and decimals and the Booster's boost.
	finalCoefficient := boostx.PlayerX(xBase, result.Boost, decimals)
	fmt.Printf("Final Coefficient Calculation:\n")
	fmt.Printf("  Formula: X' = FloorX(1 + (FloorX(X, decimals) - 1) * boost, decimals)\n")
	fmt.Printf("  X' = PlayerX(%v, %v, %d) = %v\n\n",
		xBase, result.Boost, decimals, finalCoefficient)

	// Demonstrate coefficient calculation directly
	fmt.Println("=== Coefficient Calculation Examples ===")
	examples := []struct {
		x, boost float64
		decimals int
	}{
		{2.0, 1.0, 2},       // No boost
		{2.0, 1.5, 2},       // 50% boost
		{3.0, 1.5, 2},       // Different X
		{14.95, 1.2, 2},     // 17.74; a naive math.Floor(x*100)/100 gives 17.73
		{49.503282, 1.5, 6}, // 73.754923 at six decimals
		{1.857, 1.5, 2},     // 2.27: X is floored to 1.85 before the boost
	}
	for _, ex := range examples {
		final := boostx.PlayerX(ex.x, ex.boost, ex.decimals)
		fmt.Printf("  X=%v, Boost=%v, decimals=%d -> Final=%v\n", ex.x, ex.boost, ex.decimals, final)
	}

	// === Settlement example ===
	fmt.Println("\n=== Creating Settlement (Partner -> BoostX) ===")

	settlementToken, err := boostx.CreateSettlementToken(partnerPrivateKey, boostx.SettlementParams{
		Partner:   "partner-123",
		User:      "user-456",
		Bet:       "bet-789",
		Status:    "win",
		Amount:    150.0,
		Currency:  "USD",
		Version:   time.Now().UnixMilli(), // must increase per bet; a timestamp works
		XSettle:   new(2.5),               // your coefficient before the boost; nil if none
		SettledAt: time.Now().UnixMilli(), // when you settled the bet, epoch ms
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
