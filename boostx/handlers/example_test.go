package handlers_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/handlers"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// exampleBetStore is a minimal BetStoreUpdater for demonstration.
type exampleBetStore struct{}

func (s *exampleBetStore) SetBoost(_ context.Context, _ *tokens.Booster) error { return nil }

func ExampleMount() {
	partnerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	boostxKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	keyStore := keys.NewMemoryKeyStore()
	if err := keyStore.Register("partner-id", &partnerKey.PublicKey, partnerKey, &boostxKey.PublicKey); err != nil {
		fmt.Println("error:", err)
		return
	}

	mux := http.NewServeMux()
	handlers.Mount(mux, "/api/boostx", &exampleBetStore{}, keyStore)

	fmt.Println("handlers mounted")
	// Output: handlers mounted
}
