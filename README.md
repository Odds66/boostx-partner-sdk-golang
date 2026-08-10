# boostx-partner-sdk-golang

[![Go 1.26+](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/Odds66/boostx-partner-sdk-golang/boostx.svg)](https://pkg.go.dev/github.com/Odds66/boostx-partner-sdk-golang/boostx)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/Odds66/boostx-partner-sdk-golang/actions/workflows/ci.yml/badge.svg)](https://github.com/Odds66/boostx-partner-sdk-golang/actions/workflows/ci.yml)

Go SDK for integrating with the BoostX platform as a partner.

## Installation

Requires Go 1.26+

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
    partnerPubKey, _ := boostx.LoadPublicKeyFromFile("partner_public.pem")
    boostxPubKey, _ := boostx.LoadPublicKeyFromFile("boostx_public.pem")
    partnerPrivKey, _ := boostx.LoadPrivateKeyFromFile("partner_private.pem")
    betStore := NewYourBetStore()

    // Register your partner_id's keys — partnerPub, partnerPriv, boostxPub.
    // (BoostX assigns the id and the boostx key pair.)
    keyStore := boostx.NewMemoryKeyStore()
    keyStore.Register("your-partner-id", partnerPubKey, partnerPrivKey, boostxPubKey)

    mux := http.NewServeMux()
    boostx.MountHandlers(mux, "/api/boostx", betStore, keyStore)

    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## Implementing BetStoreUpdater

Partners must implement the `BetStoreUpdater` interface:

```go
type BetStoreUpdater interface {
    SetBoost(ctx context.Context, booster *boostx.Booster) error
}
```

- **SetBoost** - Stores the boost update from BoostX

To enable the optional `/check-bet` endpoint, also implement `BetStoreChecker`:

```go
type BetStoreChecker interface {
    CheckBet(ctx context.Context, gid *boostx.GID) (active bool, err error)
}
```

- **CheckBet** - Returns true if the bet is active and eligible for boosting. This endpoint is only called by BoostX when enabled for your integration (disabled by default).

See [pkg.go.dev](https://pkg.go.dev/github.com/Odds66/boostx-partner-sdk-golang/boostx) for detailed type documentation (`GamePass`, `Booster`, `GID`).

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `{prefix}/check-bet` | POST | Check if a bet is active *(optional, requires BetStoreChecker)* |
| `{prefix}/set-boost` | POST | Receive boost updates |
| `{prefix}/verify-keys` | POST | Signed round-trip key-pair verification |

### POST /check-bet

Request body:
```json
{"checkbetJWT": "eyJhbGciOiJFUzI1NiJ9..."}
```

### POST /set-boost

Request body:
```json
{"boosterJWT": "eyJhbGciOiJFUzI1NiJ9..."}
```

### POST /verify-keys

Signed round-trip that confirms BoostX and the partner hold each other's public keys.

Request body:
```json
{"verifyKeysJWT": "eyJhbGciOiJFUzI1NiJ9..."}
```

Response body:
```json
{"result": {"responseJWT": "eyJhbGciOiJFUzI1NiJ9..."}}
```

Error body (400): `{"error": "invalid verifyKeysJWT: <reason>"}` — reason ∈ `signature`, `iss-aud`, `stale`, `shape`, `nonce-format`.

## Error Handling

The SDK provides typed errors:

- `ErrInvalidPrivateKey` / `ErrInvalidPublicKey` - Invalid ECDSA key
- `ErrInvalidGamePass` / `ErrInvalidBooster` / `ErrInvalidCheckBet` / `ErrInvalidSettlement` / `ErrInvalidVerifyKeys` - Invalid token
- `ErrVerifyKeysIssAud` / `ErrVerifyKeysStale` / `ErrVerifyKeysNonce` - VerifyKeys-specific reasons
- `ErrInvalidGID` - Invalid GID struct
- `ErrInvalidSignature` - Invalid token signature
- `ErrMissingClaim` / `ErrInvalidClaim` - Claim issues

Some of these fire earlier than BoostX would. Every token builder rejects an
empty `Partner`, `User` or `Bet` with `ErrMissingClaim`, while BoostX itself
accepts an empty `user` or `bet` and treats it as an identifier like any other.
The gate is deliberate: an empty bet id is a caller bug in every real case, and
catching it before signing beats discovering it as an unattributable game
session. Pass a placeholder if you genuinely need one. Identifiers must also be
valid UTF-8 (`ErrInvalidClaim` otherwise): an invalid byte cannot survive JSON
transport, so a token built from one could never verify.

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
    Partner:    "partner-id",
    User:       "user-id",
    Bet:        "bet-id",
    Amount:     100.0,
    Currency:   "USD",
    X:          2.0,
    XMin:       1.1,
    XMax:       10.0,
    EventTitle: "Real Madrid vs Barcelona — Match Winner: Real Madrid", // optional
})
```

### Submitting Settlements

Use the client to sign and submit settlement tokens to BoostX:

```go
partnerKey, _ := boostx.LoadPrivateKeyFromFile("partner_private.pem")
keyStore := boostx.NewMemoryKeyStore()
keyStore.Register("partner-id", nil, partnerKey, nil) // outbound needs only the signing key
client := boostx.NewClient(keyStore)

err := client.SubmitSettlement(ctx, boostx.SettlementParams{
    Partner:   "partner-id",
    User:      "user-id",
    Bet:       "bet-id",
    Status:    "win",
    Amount:    150.0,
    Currency:  "USD",
    Version:   time.Now().UnixMilli(),
    XSettle:   new(2.5), // your own coefficient, before the BoostX boost
    SettledAt: time.Now().UnixMilli(),
})
```

| Field | Required | Notes |
|-------|----------|-------|
| `Status` | yes | One of `win`, `lose`, `cancelled`, `refund`, `half_win`, `half_lose`, `cashout`, `unsettled` |
| `Amount` / `Currency` | yes | What actually reached the player; `0` for a loss, and `0` is the only accepted amount when `Status` is `unsettled`. Currency is 3 or 4 uppercase letters, e.g. `USD` or `USDT` |
| `Version` | yes | Increases per bet, need not be sequential — a millisecond timestamp works. In `[0, 2^53−1]` |
| `XSettle` | no | `*float64`. Your own coefficient the stake is multiplied by, before the boost. Finite and `>= 0` when supplied |
| `SettledAt` | yes | When **you** settled the bet, epoch milliseconds. Must be no earlier than `1e12` (2001-09-09, which rejects seconds-scale timestamps) and no more than 24 hours ahead — clocks are expected to stay in sync with BoostX |

`Partner` must be the partner id **assigned by BoostX** — the same value every
inbound Booster and CheckBet token carries in `gid.partner` — not an internal
id of your own. The SDK cannot tell the two apart (both are valid strings and
your key store may well hold a key under either), but BoostX rejects a
settlement signed under an id it did not assign, with HTTP 404. The same rule
applies to `GamePassParams.Partner`.

`Version` orders repeated settlements of the same bet: retrying a failed call
under the same version is safe, while correcting a settlement that already went
through means sending it again under a strictly higher one — if a correction can
land in the same millisecond as the original, bump the timestamp by one.
Versions of different bets are unrelated. `0` is a legal version, so the SDK
cannot tell an unset `Version` from a deliberate zero and does not try — an
omitted `Version` is sent as version `0`, not rejected.

`XSettle` is a pointer because it is optional and `0` is a legal value. Leave it
`nil` when there is no settled coefficient to report — most often for
`cancelled`, `refund` and `unsettled` — and point it at a number otherwise.
`new(0.0)` means the coefficient really was `0` (the player lost everything),
which is not the same as leaving the field out. Values below `1` are legal; the
boost only ever applies to the part of a coefficient above `1`.

To create a settlement token directly without submitting:

```go
token, err := boostx.CreateSettlementToken(privateKey, boostx.SettlementParams{
    Partner:   "partner-id",
    User:      "user-id",
    Bet:       "bet-id",
    Status:    "cancelled",
    Amount:    100.0,
    Currency:  "USD",
    Version:   time.Now().UnixMilli(),
    XSettle:   nil, // no settled coefficient for this status
    SettledAt: time.Now().UnixMilli(),
})
```

### Key Stores

The key store maps each `partner_id` to its keys; the handlers pass the request's
`partner_id`, so the store returns the right set. It's the same store as the Quick
Start — serving several `partner_id`s is just calling `Register` more than once.

The SDK ships **`MemoryKeyStore`** — an in-memory store you preload (the Quick
Start store). It satisfies both `HandlersKeyStore` and `ClientKeyStore`:

```go
ks := boostx.NewMemoryKeyStore()
// Register(partner, partnerPub, partnerPriv, boostxPub): partnerPub verifies GID
// signatures, partnerPriv signs the response, boostxPub verifies inbound BoostX JWTs.
ks.Register("partner-a", partnerAPub, partnerAPriv, boostxPubForA)
ks.Register("partner-b", partnerBPub, partnerBPriv, boostxPubForB)

boostx.MountHandlers(mux, "/api/boostx", betStore, ks)
```

`Register` is safe to call while handlers serve requests (onboarding, rotation).

For keys that live outside the process — a database, secret manager, or KMS —
implement `HandlersKeyStore` yourself (and `ClientKeyStore` for outbound). It's
three small methods keyed on `partner_id`:

```go
type HandlersKeyStore interface {
    PartnerPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error)
    PartnerPrivateKey(ctx context.Context, partner string) (*ecdsa.PrivateKey, error)
    BoostxPublicKey(ctx context.Context, partner string) (*ecdsa.PublicKey, error)
}
```

A custom store must treat its `partner` argument as authoritative: return an
error (wrap `boostx.ErrUnknownPartner` to get the 400 mapping) for an id you do
not serve, never a fixed key set regardless of the id. A store that ignores
the argument answers for whatever id the inbound token names — so if the
partner id in your own configuration ever disagrees with the one BoostX
assigned, every inbound check still passes locally and the mismatch only
surfaces as rejected outbound calls. Even a single-tenant store therefore
gates on the id — either a `MemoryKeyStore` with one `Register` call, or an
explicit check:

```go
func (s myKeyStore) PartnerPrivateKey(ctx context.Context, partner string) (*ecdsa.PrivateKey, error) {
    if partner != s.partnerID { // the id BoostX assigned, from your own config
        return nil, fmt.Errorf("%w %q", boostx.ErrUnknownPartner, partner)
    }
    return s.priv, nil
}
```

With the store gating honestly, a token addressed to any other id is rejected
with `unknown partner "<id>"` — reported on `/verify-keys` as an `iss-aud`
failure — and your own outbound signing fails just as loudly, so a wrong
configured id becomes an immediate, visible error in both directions instead
of a silent echo.

### Outbound Signing

To create a token for a specific partner_id, resolve that partner's key from the
same store the handlers use, then call the token factory:

```go
params := boostx.GamePassParams{Partner: "partner-a", /* ... */}
key, _ := ks.PartnerPrivateKey(ctx, params.Partner)
gamePassJWT, _ := boostx.CreateGamePassToken(key, params)
```

## Testing

```bash
go test ./...
```

## Example

See [examples/server](examples/server) for a complete implementation.
