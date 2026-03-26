# Changelog

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
