package client_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/client"
	"github.com/Odds66/boostx-partner-sdk-golang/boostx/keys"
)

func exampleKeyStore() *keys.StaticPrivateKeyStore {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	ks, err := keys.NewStaticPrivateKeyStore(key)
	if err != nil {
		log.Fatal(err)
	}
	return ks
}

func ExampleNew() {
	c := client.New(exampleKeyStore())

	fmt.Println("client created:", c != nil)
	// Output: client created: true
}

func ExampleNew_withBaseURL() {
	c := client.New(
		exampleKeyStore(),
		client.WithBaseURL("https://custom-api.example.com"),
	)

	fmt.Println("client created:", c != nil)
	// Output: client created: true
}

func ExampleNew_withHTTPClient() {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:    10,
			IdleConnTimeout: 60 * time.Second,
		},
	}

	c := client.New(
		exampleKeyStore(),
		client.WithHTTPClient(httpClient),
	)

	fmt.Println("client created:", c != nil)
	// Output: client created: true
}
