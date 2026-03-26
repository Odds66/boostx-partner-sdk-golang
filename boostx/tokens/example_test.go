package tokens_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

func ExampleCreateGamePassToken() {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	token, err := tokens.CreateGamePassToken(privateKey, tokens.GamePassParams{
		Partner:  "partner-123",
		User:     "user-456",
		Bet:      "bet-789",
		Amount:   100.0,
		Currency: "USD",
		X:        2.0,
		XMin:     1.1,
		XMax:     10.0,
	})
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("token created:", token != "")
	// Output: token created: true
}
