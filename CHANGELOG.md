# Changelog

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
