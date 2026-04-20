// Example HTTP server showing boostx SDK integration.
//
// This example demonstrates:
// - Loading keys from files (or generating test keys)
// - Implementing BetStoreUpdater interface
// - Mounting handlers on a mux
// - Running the server
//
// Usage:
//
//	go run ./examples/server/main.go
//
// Test with curl:
//
//	curl -X POST http://localhost:8080/api/boostx/set-boost \
//	  -H "Content-Type: application/json" \
//	  -d '{"boosterJWT": "..."}'
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx"
)

const (
	partnerID = "partner-123"
	userID    = "user-456"
	betID     = "bet-789"
)

func main() {
	// Generate test keys (in production, load from secure storage)
	partnerPrivateKey, partnerPublicKey := generateTestKeyPair("Partner")
	_, boostxPublicKey := generateTestKeyPair("BoostX")

	// Create an in-memory bet store and add a sample bet for testing
	betStore := NewMemoryBetStore()
	betStore.AddBet(betID)

	// Mount handlers on mux and add a test endpoint to create GamePass tokens
	mux := http.NewServeMux()
	mux.HandleFunc("/api/test/gamepass", func(w http.ResponseWriter, r *http.Request) {
		token, err := boostx.CreateGamePassToken(partnerPrivateKey, boostx.GamePassParams{
			Partner:    partnerID,
			User:       userID,
			Bet:        betID,
			Amount:     100.0,
			Currency:   "USD",
			X:          2.0,
			XMin:       1.1,
			XMax:       10.0,
			EventTitle: "Real Madrid vs Barcelona — Match Winner: Real Madrid",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(token))
	})

	if err := boostx.MountHandlers(mux, "/api/boostx", betStore, partnerPublicKey, boostxPublicKey); err != nil {
		log.Fatalf("Failed to mount handlers: %v", err)
	}

	// Start server
	addr := ":8080"
	fmt.Printf("Starting server on %s\n", addr)
	fmt.Println("Endpoints:")
	fmt.Println("  POST /api/boostx/check-bet  - Check if bet is active (optional)")
	fmt.Println("  POST /api/boostx/set-boost  - Receive boost update")
	fmt.Println("  GET  /api/test/gamepass     - Generate test GamePass token")
	fmt.Println()

	log.Fatal(http.ListenAndServe(addr, mux))
}

func generateTestKeyPair(name string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate %s key pair: %v", name, err)
	}
	fmt.Printf("Generated %s test key pair (P-256)\n", name)
	return privateKey, &privateKey.PublicKey
}
