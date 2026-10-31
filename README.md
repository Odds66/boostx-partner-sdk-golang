# boostx-partner-sdk-golang

[![Go 1.26+](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Go Reference](https://pkg.go.dev/badge/github.com/Odds66/boostx-partner-sdk-golang/boostx.svg)](https://pkg.go.dev/github.com/Odds66/boostx-partner-sdk-golang/boostx)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/Odds66/boostx-partner-sdk-golang/actions/workflows/ci.yml/badge.svg)](https://github.com/Odds66/boostx-partner-sdk-golang/actions/workflows/ci.yml)

Go SDK for integrating with the BoostX platform as a partner. A step-by-step quick start, and the
contract this SDK implements, are in the partner docs: [Go SDK](https://docs.boostx.cloud/sdk/go/).

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
    partnerPubKey, err := boostx.LoadPublicKeyFromFile("partner_public.pem")
    if err != nil {
        log.Fatal(err)
    }
    boostxPubKey, err := boostx.LoadPublicKeyFromFile("boostx_public.pem")
    if err != nil {
        log.Fatal(err)
    }
    partnerPrivKey, err := boostx.LoadPrivateKeyFromFile("partner_private.pem")
    if err != nil {
        log.Fatal(err)
    }
    betStore := NewYourBetStore()

    // Register your partner_id's keys — partnerPub, partnerPriv, boostxPub.
    // (BoostX assigns the id and the boostx key pair.)
    keyStore := boostx.NewMemoryKeyStore()
    if err := keyStore.Register("your-partner-id", partnerPubKey, partnerPrivKey, boostxPubKey); err != nil {
        log.Fatal(err)
    }

    // The prefix is the path of the API URL on your dashboard. That URL must be
    // HTTPS, so serve this behind your TLS front end.
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

- **SetBoost** - Applies the boost update from BoostX

The SDK verifies each Booster token's signatures but does not reject replays —
bet-flow tokens carry no expiry, and the SDK does not track rounds. BoostX can
send a round again, or deliver an older round late, so the replay rule is
yours to enforce in `SetBoost`:

- Find the bet by `Partner`, `User` and `Bet` together; a bet id alone is not
  unique across partner ids.
- Apply the update only when `booster.Round` is greater than the last round
  you applied for that bet. For any other round return `nil`, which answers
  `200`, and change nothing.
- Check and write atomically (one lock or one conditional update), so a late
  round cannot overwrite a newer one.
- Return `boostx.ErrRoundRejected`, or an error wrapping it, for a round you
  have not applied and will not apply; the handler answers
  `400 {"error":"round rejected"}`. Any other error, such as a database failure,
  is answered `500 {"error":"failed to set boost"}`. Either way BoostX does not
  retry it and the round does not count; BoostX sends it again with the
  player's first spin after reopening the game, so a bet you updated before
  refusing would fail the round check on every replay.

[examples/server](examples/server/betstore.go) implements these rules.

To enable the optional `/check-bet` endpoint, also implement `BetStoreChecker`:

```go
type BetStoreChecker interface {
    CheckBet(ctx context.Context, gid *boostx.GID) (active bool, err error)
}
```

- **CheckBet** - Returns true if the bet is active and eligible for boosting. This endpoint is only called by BoostX when enabled for your integration (disabled by default).

Answer `(false, nil)` for a bet you do not know or no longer accept. Return an
error only when you cannot check: it is answered `500`, which BoostX reads as no
verdict, so the spin is refused as retryable, and a game open treats the bet as
active.

See [pkg.go.dev](https://pkg.go.dev/github.com/Odds66/boostx-partner-sdk-golang/boostx) for detailed type documentation (`GamePassParams`, `Booster`, `GID`).

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

Response body: `{"result": {"active": true}}` or `{"result": {"active": false}}`.

Errors: `400` for `invalid request body`, `invalid checkbet token` or
`unknown partner "<id>"`; `500` for `failed to get boostx key`,
`failed to get partner key`, `failed to verify token` or `failed to check bet`.

### POST /set-boost

Request body:
```json
{"boosterJWT": "eyJhbGciOiJFUzI1NiJ9..."}
```

Response body: `{"result": {"ok": true}}`.

Errors: `400` for `invalid request body`, `invalid booster token`,
`unknown partner "<id>"` or `round rejected`; `500` for
`failed to get boostx key`, `failed to get partner key`,
`failed to verify token` or `failed to set boost`.

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
A key store error other than an unknown partner, or a nil or non-P-256 key, is answered `500`.

## Error Handling

The SDK provides typed errors:

- `ErrInvalidPrivateKey` / `ErrInvalidPublicKey` - A nil key, one not on P-256, or a private key that cannot sign
- `ErrInvalidGamePass` / `ErrInvalidBooster` / `ErrInvalidCheckBet` / `ErrInvalidVerifyKeys` - Invalid token
- `ErrVerifyKeysShape` / `ErrVerifyKeysIssAud` / `ErrVerifyKeysStale` / `ErrVerifyKeysNonce` - VerifyKeys-specific reasons, each wrapping `ErrInvalidVerifyKeys`; `VerifyKeysReason(err)` maps each to its reason string
- `ErrInvalidGID` - Invalid GID, such as a malformed signature
- `ErrInvalidSignature` - Invalid token or GID signature
- `ErrMissingClaim` / `ErrInvalidClaim` - A required value is missing, or a value is out of range
- `ErrUnknownPartner` - The key store does not serve the partner id
- `ErrRoundRejected` - Returned by your `SetBoost` for a round you will not apply; answered `400`
- `*APIError` - A settlement was not accepted; `StatusCode` is the HTTP status of the answer

Any `SubmitSettlement` error, whatever it is, means the settlement is not
delivered yet; see [Submitting Settlements](#submitting-settlements).

Every refusal of an inbound token matches both its token error and its cause:
a GID signed with another key matches `ErrInvalidBooster`, `ErrInvalidGID` and
`ErrInvalidSignature`, for example. A nil key or one not on P-256 is
`ErrInvalidPublicKey` alone, since it is a configuration problem, not a bad token; the mounted
handlers answer it `500`. Compare errors with `errors.Is`, never with `==`.

Some of these fire earlier than BoostX would. The partner docs require `User`
and `Bet` to be non-empty; BoostX does not refuse an empty one, so every token
builder does, with `ErrMissingClaim`, before signing. Identifiers must also be
valid UTF-8 (`ErrInvalidClaim` otherwise): an invalid byte cannot survive JSON
transport, so a token built from one could never verify. `CreateGamePassToken`
refuses an `X` of `0`, an `X` left unset included, with `ErrInvalidClaim`:
BoostX refuses it on the gamepass that starts a bet, but accepts it on a later
one and serves the game view-only. `NewClient`, `MountHandlers` and the handler
constructors panic on a nil key store or bet store, at startup rather than on
the first request.

`User` and `Bet` must not contain `:`. BoostX treats bets whose ids differ only
in where a `:` falls as the same bet, so the second joins the first game instead
of starting its own. The SDK does not check this.

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

Each loader reads the first block of its kind, `PRIVATE KEY` or `EC PRIVATE KEY`, and `PUBLIC KEY`,
so a file that also holds `EC PARAMETERS` or the other half of the pair loads as it is. A key kept
in an environment variable or a secret with its line breaks written as `\n` or `\r\n` loads too,
and so does one with a leading UTF-8 byte order mark.

### Creating GamePass Tokens

Create a GamePass token with `CreateGamePassToken`:

**Call this when the player opens the game, not before.** BoostX accepts a GamePassJWT only within
300 seconds of its `iat`, and only at the moment the game is opened — a URL built ahead of time and
clicked later will not start.

`CreateGamePassToken` stamps `iat` with the time of the call and adds no `exp`, so the 300 seconds
run from the moment you call it. The check is two-sided, so keep the clocks of every host that
calls it NTP-synced: a host running fast fails the same way a stale token does.

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

`Amount` is the stake in major units of `Currency`, `12.5` for twelve euros fifty, never cents. It
must be greater than `0`: BoostX refuses a gamepass whose stake is `0` on every entry, so
`CreateGamePassToken` rejects it with `ErrInvalidClaim`, an `Amount` left at its zero value included.

`X` is your own coefficient for the bet before the boost, never an X derived from a Booster token's
`boost`: BoostX boosts the `X` of every entry, so one that already carries the boost is boosted
twice. Re-enter a bet with the `X` you last issued, unless your own coefficient changed.

`XMin`, `XMax` and `XDecimals` are optional. Left at `0`, each is left out of the token and BoostX
applies its default: `1.1`, `200` and `2` decimal places. If your own limits cap X below `200`, set
`XMax`.

BoostX refuses a gamepass that starts a bet unless `X`, `XMin` and `XMax` lie within `[1.1, 200]`
and `XMin < XMax` (compared after flooring to `XDecimals`, which must be 2–6); the SDK checks only
that `X` is set, that `X`, `XMin` and `XMax` are finite and not negative, and that `XDecimals` is in
range. A later entry's `X` is not range-checked again: BoostX adopts any
finite value, and while the resulting X lies outside `[XMin, XMax]` the game is view-only, with no
round playable. Keep every `X` you issue inside `[1.1, 200]` yourself
([Validation rules (xrange)](https://docs.boostx.cloud/gamepass/#validation-rules-xrange)).

### Calculating X

`PlayerX(xBase, boost, decimals)` returns the X the player saw for a Booster token's `boost`:
`1 + (xBase - 1) × boost`, floored to the bet's `xrange.decimals`. BoostX floors `xBase` onto that
grid when it receives the gamepass and boosts the floored value, and floors by its own rule
([Flooring X](https://docs.boostx.cloud/rounds/#flooring-x)), which a plain
`math.Floor(x*100)/100` does not reproduce in every round:

```go
x := boostx.PlayerX(xBase, booster.Boost, decimals)
```

`xBase` is the `X` you signed into the gamepass of the entry that sends the round, normally the
latest one you issued: after the player reopens the game on a new `X`, BoostX boosts that one, for
every round, regular or jackpot, sent for the first time or again. The one exception is a regular
round with `final: true` that is sent again after a reopen: it keeps the `X` of the entry during
which it was first sent, because an ended game shows the `X` that ended it
([Coefficient calculation](https://docs.boostx.cloud/rounds/#coefficient-calculation)). BoostX never
sends `xBase` back, so record the `X` of every gamepass you issue for a bet. `decimals` is the bet's
`XDecimals`; `0` (unset) floors to the default `2`. With `xBase` `1.857`, `boost` `1.5` and two
decimals, the player saw `2.27`, not the `2.28` that flooring only the result gives.
`FloorX(x, decimals)` is the flooring step alone.

### Submitting Settlements

Use the client to sign and submit settlement tokens to BoostX. Build the
`SettlementParams` once, when you settle the bet, and keep them with the bet, so
that every attempt sends the same values, `Version` and `SettledAt` included:

```go
partnerKey, _ := boostx.LoadPrivateKeyFromFile("partner_private.pem")
keyStore := boostx.NewMemoryKeyStore()
keyStore.Register("partner-id", nil, partnerKey, nil) // outbound needs only the signing key
client := boostx.NewClient(keyStore)

// Once, when you settle the bet; store params with it.
settledAt := time.Now().UnixMilli()
params := boostx.SettlementParams{
    Partner:   "partner-id",
    User:      "user-id",
    Bet:       "bet-id",
    Status:    "win",
    Amount:    150.0,
    Currency:  "USD",
    Version:   settledAt,
    XSettle:   new(2.5), // your own coefficient, before the BoostX boost
    SettledAt: settledAt,
}

// Every attempt, the first and each retry, sends the stored params.
if err := client.SubmitSettlement(ctx, params); err != nil {
    // not delivered yet, whatever err is: keep params queued and send them
    // again later, with backoff; err tells you what to check if it persists
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `Status` | yes | One of `win`, `lose`, `cancelled`, `refund`, `half_win`, `half_lose`, `cashout`, `unsettled` |
| `Amount` / `Currency` | yes | What actually reached the player, in major units of `Currency`; `0` for a loss, and `0` is the only accepted amount when `Status` is `unsettled`. Currency is 3 or 4 uppercase letters, e.g. `USD` or `USDT` |
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

`SubmitSettlement` makes one attempt and returns `nil` only for BoostX's
acceptance, `200 {"result":{"ok":true}}`. Every other outcome means the
settlement is not delivered yet: any HTTP status, a `4xx` included, a network
failure or timeout, a key store error, even a value the SDK refuses before
sending. Keep the params and send the same params again, with a backoff, until
BoostX accepts them — for example over 3 days, after 1 minute, 5 minutes and
30 minutes, then hourly — and alert, and contact BoostX, if the window ends
without acceptance. Never decide from a status that a settlement is lost: a
`4xx` can come from a BoostX release that a later fix undoes, and re-sending
under the same `Version` is a no-op once BoostX holds the settlement (it answers
`200` and discards the duplicate).

Any answer other than the acceptance is an `*APIError` carrying its
`StatusCode` and `Message`: a `3xx` (redirects are never followed), a `4xx`, a
`5xx`, or a `2xx` with another body (`Message` `unexpected response`). They tell
you where to look when an alert fires:

- `401`: the partner key pair, or the partner id.
- `404` whose `Message` is `not found`: a partner id BoostX did not assign.
- Any other `404`, a `3xx`, or a `2xx` without the acceptance body: the base URL.
- `400` whose `Message` starts with `invalid-`, such as `invalid-xsettle`: that
  field.
- `5xx`: the BoostX side.

An error that is not an `*APIError` names its cause: a value the SDK refused
before sending (`ErrMissingClaim`, `ErrInvalidClaim`), your key store, or the
request itself, such as a timeout.

Queue the params, not a signed token: each attempt is signed with the key the
store holds at that moment, so a retry picks up a rotated key. A `401` during a
partner key rotation clears once the store holds the new private key.

The client posts to `https://partners-s2s.boostx.cloud` unless you pass
`client.WithBaseURL` (from `boostx/client`). Give it the scheme and host,
optionally with a path prefix, or the settlement endpoint URL itself;
surrounding whitespace and trailing slashes are ignored. Use `https://`: an
`http://` URL that redirects to HTTPS fails as a `3xx`. A client passed with
`client.WithHTTPClient` is used as is, so set its `Timeout` or give
`SubmitSettlement` a context with a deadline; the default client times out
after 30 seconds.

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

A token you build and queue yourself stays signed with the key in force when you
built it: after a partner key rotation, rebuild it under the same `Version` and
values, or it is answered `401`.

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
It replaces every key of that `partner_id`, so on a partner key rotation
register the old public key too; see
[Several partner public keys](#several-partner-public-keys).

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
not serve, never a fixed key set regardless of the id. A store that ignores the
argument answers for whatever id the inbound token names — so if the
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

Match the id byte for byte: no case-folding, trimming, normalisation, or
case-insensitive database collation. The `/verify-keys` response is signed
with `iss` set to the id your store accepted, so a store that also accepts
`Partner-A` for `partner-a` passes the integration self-test, while BoostX
refuses what you then sign under your own spelling.

Return a key or an error, never `nil, nil`: the handlers answer a missing
public key `500 {"error":"failed to verify token"}`, and `/verify-keys` a
missing partner private key `500 {"error":"failed to sign response"}`.

#### Several partner public keys

After you rotate your partner key pair, `/check-bet` and `/set-boost` keep
carrying the GID of the gamepass that created each game, signed with the old
partner private key, for as long as that game lasts. Register the new private
key with both public keys, the new one first, in one call, and keep the old
public key until the games started before the rotation have ended
([Rotating the partner key pair](https://docs.boostx.cloud/keys/#rotating-the-partner-key-pair)):

```go
ks.RegisterWithPartnerPublicKeys("partner-a",
    []*ecdsa.PublicKey{newPartnerPub, oldPartnerPub}, newPartnerPriv, boostxPubForA)
```

A GID passes when any of the keys verifies it. A custom store gets the same by
also implementing `PartnerPublicKeysStore`:

```go
type PartnerPublicKeysStore interface {
    PartnerPublicKeys(ctx context.Context, partner string) ([]*ecdsa.PublicKey, error)
}
```

Return the current key first, and an error rather than an empty list (wrap
`boostx.ErrUnknownPartner` for an id you do not serve). A store that wraps
another one, for example by embedding a `HandlersKeyStore`, must forward
`PartnerPublicKeys` too, or the handlers silently fall back to the single
`PartnerPublicKey`. Hand-written handlers verify with
`ParseBoosterTokenWithKeys` and `ParseCheckBetTokenWithKeys`.

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
