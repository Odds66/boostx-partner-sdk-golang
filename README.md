# boostx-partner-sdk-golang

Go SDK for integrating with the BoostX platform as a partner.

## Installation

Requires Go 1.21+

```bash
go get github.com/Odds66/boostx-partner-sdk-golang
```

## Quick Start

```go
package main

import (
    "log"
    "net/http"

    "github.com/Odds66/boostx-partner-sdk-golang/boostx"
)

func main() {
    gamepassPubKey, _ := boostx.LoadPublicKeyFromFile("gamepass_public.pem")
    boostPubKey, _ := boostx.LoadPublicKeyFromFile("boost_public.pem")
    betStore := NewYourBetStore()

    mux := http.NewServeMux()
    if err := boostx.MountHandlers(mux, "/api/boostx", betStore, gamepassPubKey, boostPubKey); err != nil {
        log.Fatal(err)
    }

    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## Implementing BetStoreUpdater

Partners must implement the `BetStoreUpdater` interface:

```go
type BetStoreUpdater interface {
    SetBoost(ctx context.Context, boost *boostx.Boost) error
}
```

- **SetBoost** - Stores the boost update from BoostX

To enable the optional `/checkBet` endpoint, also implement `BetStoreChecker`:

```go
type BetStoreChecker interface {
    CheckBet(ctx context.Context, identity *boostx.Identity) (active bool, err error)
}
```

- **CheckBet** - Returns true if the bet is active and eligible for boosting. This endpoint is only called by BoostX when enabled for your integration (disabled by default).

See [pkg.go.dev](https://pkg.go.dev/github.com/Odds66/boostx-partner-sdk-golang/boostx) for detailed type documentation (`GamePass`, `Boost`).

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `{prefix}/checkBet` | POST | Check if a bet is active *(optional, requires BetStoreChecker)* |
| `{prefix}/setBoost` | POST | Receive boost updates |

## Error Handling

The SDK provides typed errors:

- `ErrInvalidPrivateKey` / `ErrInvalidPublicKey` - Invalid ECDSA key
- `ErrInvalidGamePass` / `ErrInvalidBoost` - Invalid token
- `ErrInvalidSignature` - Invalid token signature
- `ErrMissingClaim` / `ErrInvalidClaim` - Claim issues

## Advanced Usage

### Key Loading

Load ECDSA P-256 keys from PEM files or raw bytes:

```go
privateKey, err := boostx.LoadPrivateKeyFromFile("private.pem")
publicKey, err := boostx.LoadPublicKeyFromFile("public.pem")

// Or from PEM bytes
privateKey, err := boostx.LoadPrivateKeyFromPEM(pemBytes)
publicKey, err := boostx.LoadPublicKeyFromPEM(pemBytes)
```

### Creating GamePass Tokens

For testing, partners can create GamePass tokens:

```go
token, err := boostx.CreateGamePassToken(privateKey, boostx.GamePassParams{
    Partner:        "partner-id",
    User:           "user-id",
    Bet:            "bet-id",
    Amount:         100.0,
    Currency:       "USD",
    X:              2.0,
    XMin:           1.1,
    XMax:           10.0,
    EventName:      "Real Madrid vs Barcelona",  // optional
    EventMarket:    "Match Winner",               // optional
    EventSelection: "Real Madrid",                // optional
})
```

### Custom Key Storage

For multi-tenant scenarios, implement `KeyStore`:

```go
type KeyStore interface {
    GamePassPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error)
    BoostPublicKey(ctx context.Context, partner, user, bet string) (*ecdsa.PublicKey, error)
}

boostx.MountHandlersWithKeyStorage(mux, "/api/boostx", betStore, yourKeyStore)
```

## Testing

```bash
go test ./...
```

## Example

See [examples/server](examples/server) for a complete implementation.
