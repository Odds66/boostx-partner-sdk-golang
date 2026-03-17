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
//	curl -X POST http://localhost:8080/api/boostx/setBoost \
//	  -H "Content-Type: application/json" \
//	  -d '{"boostJWT": "..."}'
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx"
)

func main() {
	// Generate test keys (in production, load from secure storage)
	partnerPrivateKey, partnerPublicKey := generateTestKeyPair("Partner")
	_, boostXPublicKey := generateTestKeyPair("BoostX")

	// Create in-memory bet store
	betStore := NewMemoryBetStore()

	// Add a sample bet for testing
	sampleBet := &StoredBet{
		BetID:  "bet-789",
		Active: true,
	}
	betStore.bets["bet-789"] = sampleBet

	// Mount handlers on mux
	mux := http.NewServeMux()
	if err := boostx.MountHandlers(mux, "/api/boostx", betStore, partnerPublicKey, boostXPublicKey); err != nil {
		log.Fatalf("Failed to mount handlers: %v", err)
	}

	// Add a test endpoint to create GamePass tokens
	mux.HandleFunc("/api/test/gamepass", func(w http.ResponseWriter, r *http.Request) {
		token, err := boostx.CreateGamePassToken(partnerPrivateKey, boostx.GamePassParams{
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
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(token))
	})

	// Start server
	addr := ":8080"
	fmt.Printf("Starting server on %s\n", addr)
	fmt.Println("Endpoints:")
	fmt.Println("  POST /api/boostx/checkBet  - Check if bet is active (optional)")
	fmt.Println("  POST /api/boostx/setBoost  - Receive boost update")
	fmt.Println("  GET  /api/test/gamepass    - Generate test GamePass token")
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

// StoredBet represents a bet stored in the bet store.
type StoredBet struct {
	BetID  string
	Active bool
	Boost  *boostx.Boost
}

// MemoryBetStore is a simple in-memory implementation of BetStoreUpdater.
type MemoryBetStore struct {
	mu   sync.RWMutex
	bets map[string]*StoredBet
}

// NewMemoryBetStore creates a new in-memory bet store.
func NewMemoryBetStore() *MemoryBetStore {
	return &MemoryBetStore{
		bets: make(map[string]*StoredBet),
	}
}

// CheckBet returns true if bet is active.
// Implementing BetStoreChecker is optional — the /checkBet endpoint is only
// registered when the BetStoreUpdater also implements this method.
func (s *MemoryBetStore) CheckBet(ctx context.Context, identity *boostx.Identity) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bet, ok := s.bets[identity.Bet]
	if !ok {
		return false, nil
	}
	return bet.Active, nil
}

// SetBoost stores the boost update.
func (s *MemoryBetStore) SetBoost(ctx context.Context, boost *boostx.Boost) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bet, ok := s.bets[boost.Bet]
	if !ok {
		return fmt.Errorf("bet not found: %s", boost.Bet)
	}

	bet.Boost = boost
	fmt.Printf("Stored boost for bet %s: round=%d, boost=%.2f, final=%v\n",
		boost.Bet, boost.Round, boost.Boost, boost.Final)

	return nil
}
