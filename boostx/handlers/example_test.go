package handlers_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/handlers"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// exampleBetStore is a minimal BetStoreUpdater for demonstration.
type exampleBetStore struct{}

func (s *exampleBetStore) SetBoost(_ context.Context, _ *tokens.Booster) error { return nil }

// exampleKeyStore is a minimal KeyStore for demonstration.
type exampleKeyStore struct {
	key *ecdsa.PublicKey
}

func (ks *exampleKeyStore) PartnerPublicKey(_ context.Context, _, _, _ string) (*ecdsa.PublicKey, error) {
	return ks.key, nil
}

func (ks *exampleKeyStore) BoostxPublicKey(_ context.Context, _, _, _ string) (*ecdsa.PublicKey, error) {
	return ks.key, nil
}

func ExampleMount() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	betStore := &exampleBetStore{}
	keyStore := &exampleKeyStore{key: &key.PublicKey}

	mux := http.NewServeMux()
	handlers.Mount(mux, "/api/boostx", betStore, keyStore)

	fmt.Println("handlers mounted")
	// Output: handlers mounted
}
