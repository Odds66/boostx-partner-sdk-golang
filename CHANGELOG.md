# Changelog

## v0.10.1

### Bug Fixes
- Fix GID signatures for identifiers containing `&`, `<`, `>`, U+2028 or U+2029. A GID signature covers the canonical bytes `{"partner":…,"user":…,"bet":…}`, which carry only the escapes JSON requires — `"`, `\` and the C0 controls. `encoding/json` escapes those five characters as well and offers no setting that stops it, so a GID built from an identifier containing any of them was signed over the wrong bytes, and every token carrying that GID was rejected as if the key were wrong. `BuildGID` and `VerifyGID` now use a hand-written encoder that matches the contract. Note the bug could not surface in a round-trip test — the two functions shared the faulty encoder and so agreed with each other; the new `TestCanonicalGIDPayloadMatchesJSONStringify` pins the bytes against independently generated vectors instead
- Accept `0` as a settlement `Version`. The valid range is `[0, 2^53−1]`; `0` was previously reported as `ErrMissingClaim`, which refused a counter that legitimately starts at zero. There is consequently no "version missing" error any more — the zero value is a real version, indistinguishable from an unset field, and an omitted `Version` is sent as `0`
- Reject identifiers that are not valid UTF-8 with `ErrInvalidClaim` when building a GID. Such an identifier cannot survive JSON transport — the token payload carries `U+FFFD` replacements while the GID signature covers the original bytes — so every token carrying it was rejected as a signature failure. `BuildGID` and the `Create*Token` functions that embed a GID now fail fast instead

## v0.10.0

### Breaking Changes
- Rename `Result` to `Status` on `SettlementParams` and `Settlement`, and replace the four accepted values with eight: `win`, `lose`, `cancelled`, `refund`, `half_win`, `half_lose`, `cashout`, `unsettled`. `cancelled` carries over unchanged; `won` → `win`, `lost` → `lose`, `refunded` → `refund`. The retired spellings are rejected with `ErrInvalidClaim`
- Add `Version int64` to `SettlementParams` and `Settlement` — **required**: `0` is reported as `ErrMissingClaim`, a negative value or one above 2^53−1 as `ErrInvalidClaim`. Version orders repeated settlements of one bet: retry a failed call unchanged, and correct a settlement that already went through by sending it again under a strictly higher version. Versions need not be sequential — a millisecond timestamp works, bumped by one if a correction lands in the same millisecond
- Add `SettledAt int64` to `SettlementParams` and `Settlement` — **required**. Epoch milliseconds, recording when the partner settled the bet. Must be no earlier than `1e12` (2001-09-09, a floor that also rejects seconds-scale timestamps) and no more than 24 hours in the future; `0` is reported as `ErrMissingClaim`, any other out-of-range value as `ErrInvalidClaim`
- Add `XSettle *float64` to `SettlementParams` and `Settlement` — optional. The partner's own coefficient the stake is multiplied by, before the boost. It is a pointer because `0` is a legal value: `nil` omits the field and means "no settled coefficient" (typically `cancelled`, `refund` and `unsettled`), while a pointer to `0` reports a coefficient that really was zero. An absent field and an explicit `null` parse alike, back to `nil`. When supplied it must be finite and `>= 0`; values below `1` are accepted
- Reject a settlement whose `Status` is `unsettled` unless `Amount` is exactly `0` (`ErrInvalidClaim`)
- Validate `SettlementParams.Currency` as 3 or 4 uppercase letters (e.g. `USD`, `USDT`); any other shape is rejected with `ErrInvalidClaim` before signing

### Wire Format Changes
- Settlement payload: `{iat, settlement: {gid, result, payout}}` → `{iat, settlement: {gid, status, payout, version, xSettle?, settledAt}}`
- `xSettle` is the only optional member: it is omitted entirely when `XSettle` is `nil`, and serialized as `0` — never dropped — when it points at zero

## v0.9.3

### New Features
- Add `Demo` field to `GamePass` and `GamePassParams` — a boolean that marks a demo/test bet via `gamepass.demo`
- Optional on the wire: omit (or set to `false`) for real bets — only `true` is serialized

## v0.9.0

### Breaking Changes
- Replace the direction-agnostic `CreateVerifyKeysToken` / `ParseVerifyKeysToken` with four direction-explicit functions that bake in `BoostxIdentity` and take only the partner ID (wire format unchanged — SDK ergonomics only):
  - `CreateVerifyKeysRequestToken(boostxPriv, partnerID, nonce)` — BoostX → partner request (iss="boostx", aud=partnerID)
  - `ParseVerifyKeysRequestToken(token, boostxPub, partnerID, maxSkew)` — verifies a BoostX → partner request
  - `CreateVerifyKeysResponseToken(partnerPriv, partnerID, nonce)` — partner → BoostX response (iss=partnerID, aud="boostx")
  - `ParseVerifyKeysResponseToken(token, partnerPub, partnerID, maxSkew)` — verifies a partner → BoostX response
- Replace the single `VerifyKeys` result struct with direction-specific `VerifyKeysRequest` / `VerifyKeysResponse`, each exposing `PartnerID` (from `aud` on requests, `iss` on responses) and `Nonce` — the redundant `Issuer`/`Audience` fields are dropped since the parse functions already validate them
- Rename `ExtractVerifyKeysAudience` to `ExtractVerifyKeysRequestPartner` — request-side partner-ID extraction for key lookup; now also re-exported from the root `boostx` package
- Remove facade re-exports that no SDK function produces or consumes: the `GamePass`, `Settlement`, `Money`, and `RegisteredClaims` type aliases — outbound flows use `GamePassParams`/`SettlementParams` with `Create*Token`, never the types. Reference `boostx/tokens` directly if you used these
- Make the SDK multi-tenant throughout (keyed by `partner_id`) and remove the single-tenant key-store types and methods:
  - Added `MemoryKeyStore`, an in-memory store keyed by `partner_id`: `NewMemoryKeyStore()` (no args), then add partners with `Register(partnerID, partnerPub, partnerPriv, boostxPub)`. Any key may be nil for a partner that only fills some roles (e.g. `Register(id, nil, priv, nil)` for outbound signing)
  - Removed the single-tenant `StaticKeyStore`, `StaticPublicKeyStore`, and `StaticPrivateKeyStore` (with their constructors and `LoadFromFiles`/`LoadFromPEM`) — a `MemoryKeyStore` with only the public keys, or only the private key, covers the verify-only and sign-only roles they served
  - `MountHandlers(mux, prefix, store, keyStore)` now takes a key store instead of three raw keys; the old raw-keys form and `MountHandlersWithKeyStorage` are removed (a single mount function remains). Single-tenant partners register their one `partner_id`
  - The SDK ships only the in-memory `MemoryKeyStore`; for keys that live elsewhere (database, secret manager, KMS), implement `HandlersKeyStore`/`ClientKeyStore` directly (three methods keyed on `partner_id`)
  - The `HandlersKeyStore`/`ClientKeyStore` methods now take `(ctx, partner)` instead of `(ctx, partner, user, bet)` — keys are per-partner_id, so `user`/`bet` were never used; custom implementations update their signatures
  - The mounted handlers respond `400` (not `500`) when the key store reports an unknown partner_id; `MemoryKeyStore` lookups wrap the new exported `keys.ErrUnknownPartner`, which custom stores can return to opt into the same mapping
- Rename `ExtractBoosterClaims`/`ExtractCheckBetClaims` to `ExtractBoosterPartner`/`ExtractCheckBetPartner`, now returning just the `partner_id` (`(string, error)`) instead of `(partner, user, bet, error)` — the handlers need only the partner for key lookup, matching `ExtractVerifyKeysRequestPartner`

### New Features
- Re-export the individual partner-side handler constructors from the root `boostx` package — `NewSetBoostHandler`, `NewVerifyKeysHandler`, `NewCheckBetHandler`, each returning an `http.Handler` — so the endpoints can be mounted on a non-stdlib router (gin, echo, chi, …) without `MountHandlers` (which requires `*http.ServeMux`)
- Re-export the inbound token parsers `ParseBoosterToken` / `ExtractBoosterPartner` and `ParseCheckBetToken` / `ExtractCheckBetPartner` from the root `boostx` package, so the `/set-boost` and `/check-bet` handlers can be hand-written entirely against the facade (no `boostx/tokens` import). Each `Parse*` verifies both the BoostX JWT signature and the embedded partner GID signature
- Add `VerifyKeysReason(err)` — maps a verify-keys parse failure to its wire reason string (`shape` / `iss-aud` / `stale` / `nonce-format` / `signature`), pairing with the reason-specific `ErrVerifyKeys*` sentinels the parse functions return

### Hardening
- Reject `partnerID == "boostx"` (the `BoostxIdentity` value) across the verify-keys API — the create/parse functions return `ErrInvalidClaim`, and `ExtractVerifyKeysRequestPartner`/the inbound `/verify-keys` handler reject a request whose `aud` is `"boostx"` as `shape`. A partner named `boostx` would make request claims (`{iss:"boostx", aud:"boostx"}`) and response claims identical, leaving only the signing key to distinguish direction.

## v0.8.4

### New Features
- Add `XDecimals` field to `GamePass` and `GamePassParams` — carries the `xrange.decimals` value from the backend, controlling how many decimal places X is floored to (integer in [2, 6], default 2)
- Optional on the wire: omit (or set to 0) to let the backend default to 2

## v0.8.3

### Breaking Changes
- `MountHandlers` now takes `partnerPrivKey *ecdsa.PrivateKey` as its final argument. `/verify-keys` is always registered alongside `/set-boost` and `/check-bet`.
- `HandlersKeyStore` (aka `handlers.KeyStore`) gains a `PartnerPrivateKey` method. Multi-tenant implementations must add it; `StaticKeyStore` already satisfies it.

### New Features
- Add `POST /verify-keys` inbound handler — signed round-trip that confirms BoostX and the partner hold each other's public keys
- Add `VerifyKeys` token type with `CreateVerifyKeysToken`, `ParseVerifyKeysToken`, and `ExtractVerifyKeysAudience`
- Add protocol constant `BoostxIdentity = "boostx"` (used as `iss` on requests and `aud` on responses)
- Add sentinel errors `ErrInvalidVerifyKeys`, `ErrVerifyKeysShape`, `ErrVerifyKeysIssAud`, `ErrVerifyKeysStale`, `ErrVerifyKeysNonce` — reason-specific errors wrap the generic sentinel
- Add wire-reason constants `VerifyKeysReason{Shape,IssAud,Stale,NonceFormat,Signature}` and `VerifyKeysReason(err) string` to map errors to the protocol reason strings (`shape` / `iss-aud` / `stale` / `nonce-format` / `signature`)

## v0.7.0

### Breaking Changes
- Consolidate GamePass `event` payload from `{name, market, selection}` into single `{title}` field (matches backend wire format)
- `GamePass` struct: `EventName`, `EventMarket`, `EventSelection` → `EventTitle`
- `GamePassParams`: `EventName`, `EventMarket`, `EventSelection` → `EventTitle`
- JWT wire format: `event.name` / `event.market` / `event.selection` → `event.title`

## v0.6.1

### Breaking Changes
- Rename `GamePassPublicKey` to `PartnerPublicKey`
- Rename `BoosterPublicKey` to `BoostxPublicKey`
- Rename `SettlementPrivateKey` to `PartnerPrivateKey`
- Split `StaticKeyStore` into `StaticPublicKeyStore` + `StaticPrivateKeyStore`
- `client.New()` now requires a `KeyStore` as first argument
- `SubmitSettlement` accepts `SettlementParams` instead of raw JWT string

### New Features
- Add `client.KeyStore` interface for resolving signing keys
- Add `StaticPrivateKeyStore` for single-key signing scenarios
- Add `StaticKeyStore` composite type combining public + private key stores

## v0.5.0

### Breaking Changes
- Rename `/setBoost` route to `/set-boost` (kebab-case, matches backend)
- Rename `/checkBet` route to `/check-bet` (kebab-case, matches backend)
- `/set-boost` now returns `{"result":{"ok":true}}` instead of bare 200
- `/check-bet` now returns `{"result":{"active":bool}}` instead of `{"active":bool}`
- Upgrade minimum Go version from 1.21 to 1.26

### New Features
- Add testable examples for tokens, handlers, and client packages
- Add GitHub Actions CI workflow with test and vet steps
- Add method-aware ServeMux routing
- Add `t.Context()` and generic `errors.AsType[T]` usage

## v0.4.0

### New Features
- Add outbound `Client` (`boostx/client` package) — the first outbound HTTP client in the SDK
- Add `SubmitSettlement` method for posting signed settlement JWTs to `POST /api/integration/settlement`
- Add `NewClient` factory with functional options: `WithBaseURL`, `WithHTTPClient`
- Re-export `APIError` from root `boostx` package

## v0.3.0

### Breaking Changes
- Replace `Identity` with `GID` (Game ID) — a signed struct with `{partner, user, bet, signature}` instead of a nested JWT sub-token
- Rename `Boost` type to `Booster`, `ParseBoostToken` to `ParseBoosterToken`, `ExtractBoostClaims` to `ExtractBoosterClaims`
- Rename `ErrInvalidBoost` to `ErrInvalidBooster`, remove `ErrInvalidIdentity`
- Rename `KeyStore.BoostPublicKey` to `KeyStore.BoosterPublicKey`
- `BetStoreUpdater.SetBoost` now takes `*Booster` instead of `*Boost`
- `BetStoreChecker.CheckBet` now takes `*GID` instead of `*Identity`
- Request body field `boostJWT` renamed to `boosterJWT`, `identityJWT` renamed to `checkbetJWT`

### New Features
- Add `CheckBet` token type and `ParseCheckBetToken` for /check-bet endpoint validation
- Add `Settlement` token type and `CreateSettlementToken` for bet settlement reporting
- Add `Money` type for structured monetary amounts
- Add `BuildGID` and `VerifyGID` functions for GID creation and verification

### Wire Format Changes
- JWT payloads now use nested structure under root keys: `gamepass`, `booster`, `checkbet`, `settlement`
- GamePass payload: `{iat, gamepass: {gid, stake, xrange, event}}`
- Booster payload: `{iat, booster: {gid, round, boost, final, jackpot}}`
- CheckBet payload: `{iat, checkbet: {gid}}`
- Settlement payload: `{iat, settlement: {gid, result, payout}}`

## v0.2.0

### Breaking Changes
- Split `BetStore` into `BetStoreUpdater` (required) and `BetStoreChecker` (optional)
- Replace `CreateGamePassToken` positional args with `GamePassParams` struct
- Remove `/getBet` endpoint, `BetInfo`, and `BetResult` types
- `/setBoost` now returns bare 200 OK instead of JSON empty object

### New Features
- Add `EventName`, `EventMarket`, `EventSelection` fields to GamePass tokens
- `/checkBet` endpoint registered conditionally via `BetStoreChecker` interface

## v0.1.0
- Initial release
