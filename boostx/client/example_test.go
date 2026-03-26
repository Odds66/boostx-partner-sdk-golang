package client_test

import (
	"fmt"
	"net/http"
	"time"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/client"
)

func ExampleNew() {
	c := client.New()

	fmt.Println("client created:", c != nil)
	// Output: client created: true
}

func ExampleNew_withBaseURL() {
	c := client.New(
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
		client.WithHTTPClient(httpClient),
	)

	fmt.Println("client created:", c != nil)
	// Output: client created: true
}
