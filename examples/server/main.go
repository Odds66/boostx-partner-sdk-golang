// Example HTTP server showing boostx SDK integration.
//
// This example demonstrates a partner server serving several partner_ids:
// - A MemoryKeyStore holding each partner_id's keys
// - Implementing the BetStoreUpdater interface
// - Mounting handlers with MountHandlers (keys selected by partner_id)
// - Creating outbound GamePass tokens (key resolved from the store by partner_id)
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
	partnerA = "partner-a"
	partnerB = "partner-b"
	userID   = "user-456"
)

func main() {
	// Build a multi-tenant key store: one key set per partner_id. BoostX mints a
	// distinct BoostX key pair per partner_id at registration; we generate one
	// per partner here. In production, register from secure storage (or implement
	// HandlersKeyStore for a DB/secret manager).
	keyStore := boostx.NewMemoryKeyStore()
	for _, id := range []string{partnerA, partnerB} {
		partnerPriv, partnerPub := generateTestKeyPair("Partner " + id)
		_, boostxPub := generateTestKeyPair("BoostX " + id)
		if err := keyStore.Register(id, partnerPub, partnerPriv, boostxPub); err != nil {
			log.Fatalf("register %s: %v", id, err)
		}
	}

	// In-memory bet store with a sample bet per partner flow.
	betStore := NewMemoryBetStore()
	betStore.AddBet("bet-a")
	betStore.AddBet("bet-b")

	mux := http.NewServeMux()
	// GET /api/test/gamepass?partner=partner-a — sign a GamePass for that partner.
	mux.HandleFunc("/api/test/gamepass", func(w http.ResponseWriter, r *http.Request) {
		pid := r.URL.Query().Get("partner")
		if pid == "" {
			pid = partnerA
		}
		params := boostx.GamePassParams{
			Partner:    pid,
			User:       userID,
			Bet:        "bet-a",
			Amount:     100.0,
			Currency:   "USD",
			X:          2.0,
			XMin:       1.1,
			XMax:       10.0,
			XDecimals:  2,
			EventTitle: "Real Madrid vs Barcelona — Match Winner: Real Madrid",
			Demo:       r.URL.Query().Get("demo") == "true", // optional: flag a demo/test session
		}
		// Resolve this partner's signing key from the same store the handlers use.
		key, err := keyStore.PartnerPrivateKey(r.Context(), params.Partner)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		token, err := boostx.CreateGamePassToken(key, params)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(token))
	})

	// Multi-tenant: the handlers select each partner_id's keys from keyStore.
	boostx.MountHandlers(mux, "/api/boostx", betStore, keyStore)

	addr := ":8080"
	fmt.Printf("Starting multi-tenant server on %s (partners: %s, %s)\n", addr, partnerA, partnerB)
	fmt.Println("Endpoints:")
	fmt.Println("  POST /api/boostx/check-bet   - Check if bet is active (optional)")
	fmt.Println("  POST /api/boostx/set-boost   - Receive boost update")
	fmt.Println("  POST /api/boostx/verify-keys - Signed round-trip key verification")
	fmt.Println("  GET  /api/test/gamepass?partner=partner-a - Generate a GamePass for a partner")
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
