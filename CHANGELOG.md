# Changelog

## v0.12.0

The last release of this module. The SDK continues as [`github.com/boostxinnovation/boostx-partner-sdk-go`](https://github.com/boostxinnovation/boostx-partner-sdk-go), whose v1.0.0 has the same packages and API as this release. `go.mod` marks this module deprecated, so `go get` and `go list -m -u` point there. To move, replace the import path and run `go get github.com/boostxinnovation/boostx-partner-sdk-go@v1.0.0`.

### New Features
- Verify the GID on `/set-boost` and `/check-bet` against several partner public keys, so a game started before a partner key rotation, whose GID keeps the old signature, keeps working. `MemoryKeyStore.RegisterWithPartnerPublicKeys` registers the current key first and the keys still valid for open games after it, and `PartnerPublicKeys` returns them; a custom store opts in by implementing the optional `PartnerPublicKeysStore` interface, which the handlers prefer over `KeyStore.PartnerPublicKey`. `tokens.ParseBoosterTokenWithKeys` and `ParseCheckBetTokenWithKeys` take the list directly. `KeyStore` itself is unchanged
- Add `ErrRoundRejected`. A `SetBoost` that returns it, for a round you have not applied and will not apply, is answered `400` `{"error":"round rejected"}`; any other error is still answered `500`
- `WithBaseURL` takes the Settlement endpoint your dashboard shows as well as the host, and ignores surrounding ASCII whitespace (space, tab, CR, LF, VT, FF) and trailing slashes
- Add `StatusWin`, `StatusLose`, `StatusCancelled`, `StatusRefund`, `StatusHalfWin`, `StatusHalfLose`, `StatusCashout` and `StatusUnsettled`, the eight settlement statuses, to `boostx` and `boostx/tokens`. `SettlementParams.Status` stays a `string`
- `Booster` and `CheckBet` carry `IssuedAt`, the token's `iat` in Unix seconds as BoostX sent it. The SDK applies no age check; if you add one, allow for retries, which send the same token again
- The conformance vectors now come from [boostx-partner-sdk-spec v1.0.0](https://github.com/boostxinnovation/boostx-partner-sdk-spec/tree/v1.0.0), mirrored in `testdata/spec/`; `SPEC_VERSION` pins the spec tag and commit

### Bug Fixes
- `SubmitSettlement` returns `nil` only for BoostX's acceptance, a `2xx` whose body is `{"result":{"ok":true}}`; any other `2xx` is an `*APIError` with the message `unexpected response`. Any `2xx` used to count as delivered, an HTML page from a wrong host included. The first 64 KiB of the body are read, and must be one JSON object in valid UTF-8 without a byte order mark; member names match exactly, and the last of a repeated name counts
- `NewClient` panics on a base URL that, once trimmed, does not start with `http://` or `https://` followed by a host, an empty one included, where every `SubmitSettlement` used to fail; on a `nil` `*MemoryKeyStore`, where the first `SubmitSettlement` used to panic; and on an `http.Client` whose `Timeout` is negative
- `SubmitSettlement` given a context that is already done returns its error before calling the key store
- A cancellation or failure while `SubmitSettlement` reads the answer's body is returned as that error, whatever the status, so a cancellation matches `context.Canceled`; on a non-`2xx` it was an `*APIError`
- The settlement client follows no redirect: a `3xx` is an `*APIError`, and the `http.Client` you pass is not modified. A followed `301` turned the `POST` into a `GET` without a body, answered `404`
- A base URL with a trailing slash no longer posts to `//api/integration/settlement`, which was answered `404`
- A key that is `nil`, not on P-256, missing its scalar or coordinates, or whose point is not on the curve gives `ErrInvalidPrivateKey` or `ErrInvalidPublicKey` instead of a panic or a signature BoostX refuses; in a list of partner public keys such a key is skipped. Every builder checks its private key before any parameter. A key store that returns an unusable key is answered `500` `failed to verify token`, not `400`
- `CreateGamePassToken` rejects an `X` of `0`, an `X` left unset included, with `ErrInvalidClaim`. BoostX refuses it on the gamepass that starts a bet and, on a later entry, adopts it and serves the game view-only
- `CreateGamePassToken` rejects a non-empty `Currency` that is not 3 or 4 uppercase ASCII letters, `usd` included, with `ErrInvalidClaim`, the rule the settlement payout currency already follows; an empty one is still `ErrMissingClaim`, and the code is sent as given
- `CreateGamePassToken` rejects an `Amount` below `0.01`, the smallest stake BoostX accepts in any currency, with `ErrInvalidClaim`
- `VerifyGID` and the Booster and CheckBet parsers accept only the canonical GID signature form, 86 characters of unpadded base64url, which BoostX requires since 2026-10-30. A signature in another form, like one that no key verifies, matches both `ErrInvalidGID` and `ErrInvalidSignature`
- `/verify-keys` compares the request's `iat` with your clock in whole seconds, as BoostX does
- `CreateVerifyKeysRequestToken` and `CreateVerifyKeysResponseToken` reject a `partnerID` that is not valid UTF-8 with `ErrInvalidClaim`, after the nonce. It used to be signed with U+FFFD in place of the invalid bytes, so the token named another partner
- `LoadPrivateKeyFromPEM` and `LoadPrivateKeyFromFile` refuse a key whose embedded public key, the optional one a SEC1 key carries on its own or inside PKCS#8, is not the uncompressed point of its private scalar, with `ErrInvalidPrivateKey`. It used to be ignored, so a file whose two halves disagree loaded and signed as the scalar's key. A key without one still loads
- `LoadPrivateKeyFromPEM` and `LoadPrivateKeyFromFile` refuse a key that is more than its structure, with `ErrInvalidPrivateKey`: bytes after the key, or after the SEC1 key inside a PKCS#8 one; a PKCS#8 version other than 0, or any field after the private key but attributes; an AlgorithmIdentifier without the P-256 curve; a SEC1 key of another version, with an unknown or repeated field, or whose curve inside a PKCS#8 key is not P-256. `x509` accepted these, reading the curve of a PKCS#8 key from its AlgorithmIdentifier alone
- The PEM loaders read the earliest block whose label is their own, `PRIVATE KEY` (PKCS#8 only) or `EC PRIVATE KEY` (SEC1 only) and `PUBLIC KEY`, skipping any other, so `openssl ecparam` output with an `EC PARAMETERS` block first loads. They read a literal `\n` as a line break, as environment variables often carry it, and ignore text around the block, a byte order mark included; an indented or one-line body loads. An encrypted key is refused with a message to decrypt it first. A file the loader cannot read matches both the key error and the operating system's error, such as `fs.ErrNotExist`
- `LoadPublicKeyFromPEM` and `LoadPublicKeyFromFile` refuse, with `ErrInvalidPublicKey`, a public key whose BIT STRING declares unused bits, as BoostX does. Such a key used to load, its point read shifted by the declared bits
- Inbound tokens are read as BoostX writes them. Member names match exactly, case included, and the last of a repeated name counts, whole. Each segment must be canonical unpadded base64url, used exactly as received; the header and payload must each be one JSON object in valid UTF-8. Only `alg` and `crit` are read from the header: an `alg` other than the string `"ES256"`, any `crit`, or a signature segment that is not 64 bytes of canonical base64url is `ErrInvalidSignature`, while a header that is not a JSON object is a malformed token, and other header members are ignored whatever their type
- An inbound token whose header or payload escapes a lone surrogate, a U+D800 to U+DFFF escape that is not half of a high-then-low pair, is a malformed token (`shape` on `/verify-keys`), refused by the extractors and parsers alike, so the handlers answer it `400`; it used to be read as U+FFFD
- The Booster and CheckBet parsers check every claim: `iat`, and on a Booster an integer `round` of at least `1`, a finite `boost` above `0`, and `final` and `jackpot` as JSON booleans, all required, plus `gid` as an object of four strings. Integers are judged by value, so `3.0` is `3`. An `exp` or `nbf` must be a number and in force. A missing claim used to read as `0` or `false`
- `ExtractBoosterPartner` and `ExtractCheckBetPartner` run the same claim checks as the parsers, and `ExtractVerifyKeysRequestPartner` the same claim-type checks, so the handlers answer such a token `400` before calling your key store
- The verify-keys parsers judge `iat` and `nonce` by value: `1793436254.0` is a valid `iat` and `5.0` the nonce `5`. A `nonce` that is not an integer from `1` to `2147483647`, a string or fraction included, is `nonce-format`; an `iss`, `aud`, `iat` or `verifyKeys` of the wrong JSON type, or an `iat` beyond `2^53−1`, is `shape`; an `exp` that has passed or an `nbf` still ahead is `stale`
- `MemoryKeyStore.Register` and `RegisterWithPartnerPublicKeys` refuse a key that is not a usable P-256 key of its role, with `ErrInvalidPublicKey` or `ErrInvalidPrivateKey`, and keep the keys registered before. They check the keys in the order of their parameters, so with both the partner private key and the BoostX public key unusable the error is `ErrInvalidPrivateKey`. A lookup for a role registered without a key fails with that role's key error
- `FloorX` and `PlayerX` return `NaN` for a `decimals` outside 2–6, `0` still meaning 2, where they returned a plausible X
- `SubmitSettlement` bounds each attempt with one time limit, from the key store lookup to the end of the answer: the `http.Client`'s `Timeout`, or 30 seconds when it is `0`. A `nil` context means no cancellation
- The handlers read the request body whole: at most 64 KiB in all, valid UTF-8, one JSON object with nothing after it, and the token under its exact name (`boosterJWT`, `checkbetJWT`, `verifyKeysJWT`) as a string or `null`. Anything else is answered `400` `{"error":"invalid request body"}`. Trailing data, invalid UTF-8 and whitespace past 64 KiB used to pass, and the token's name matched in any case
- `NewSetBoostHandler`, `NewCheckBetHandler` and `NewVerifyKeysHandler` answer a method other than `POST` with `405` `{"error":"method not allowed"}` and `Allow: POST`, on any router; they used to process a `GET` like a `POST`. Under `MountHandlers`, `http.ServeMux` still answers it, with its own body
- `MountHandlers` panics at startup on a prefix that is not empty or a clean path starting with `/`. A prefix with no leading `/`, a host-qualified one included, used to register as a host pattern, one holding `{` or `}` as a wildcard pattern, and one holding a space or a tab without error; a `//`, `.` or `..` segment already panicked, and now gets a message that states the rule
- The hand-written `/verify-keys` handler in the examples answers as `NewVerifyKeysHandler` does: a JSON `{"error": …}` on every refusal, `400` `invalid verifyKeysJWT: iss-aud (unknown partner "<id>")` for an id the key store does not serve, `500` for any other key-store failure, and a 64 KiB body cap. It answered in plain text, and `404` for an unserved id, which BoostX's key check counts as a failure

### Changes to check when you upgrade
- Every refusal of an inbound token matches its token error (`ErrInvalidBooster`, `ErrInvalidCheckBet`, `ErrInvalidGamePass`, `ErrInvalidVerifyKeys`) and its cause with `errors.Is`, a GID signature that no key verifies also matches `ErrInvalidGID`, and one that is not canonical also matches `ErrInvalidSignature`. Error texts gain prefixes: compare errors with `errors.Is`, never by their text
- `MountHandlers`, the `New*Handler` constructors and `NewClient` panic on a `nil` bet store or key store; `WithHTTPClient(nil)` keeps the default client. `NewClient` also panics on a `nil` `*MemoryKeyStore`, on an invalid base URL, an empty one included, and on a negative `Timeout`: start the client once in staging before you upgrade
- A test double for the settlement endpoint must answer `{"result":{"ok":true}}`, names spelled exactly: a bare `200` or `204` is now an `*APIError`
- `APIError.Message` for an answer whose body has no non-empty `error` string is `HTTP <status>`, such as `HTTP 404`, instead of the status text (`Not Found`), and `error` is read under that exact name only. Diagnose from `StatusCode`, or from `Message` being `not found`, not from the status text
- `ErrInvalidSettlement` is removed: nothing returned it
- A Booster or CheckBet token without `iat`, or a Booster whose `round`, `boost`, `final` or `jackpot` is missing or of the wrong JSON type, is refused with `ErrMissingClaim` or `ErrInvalidClaim`. BoostX always sends them, but tokens you sign for your own tests must carry them, with `round` of at least `1` and `boost` above `0`
- Claim names are case-sensitive: a token that spelled a claim in another case used to be read, and is now refused as missing that claim. The same holds for `ParseJWT`'s header, while `ParseJWT` and `ExtractJWTClaims` still fill your struct by `encoding/json`'s rules
- `ExtractBoosterPartner`, `ExtractCheckBetPartner` and `ExtractVerifyKeysRequestPartner` refuse a token whose claims fail, where they used to return its partner id
- `ParseJWT` and `ExtractJWTClaims` refuse a padded or otherwise non-canonical segment, a payload that is not one JSON object (`null` included), invalid UTF-8 and a lone surrogate escape. An undecodable signature segment and a `crit` header are now `ErrInvalidSignature`; a header that is not a JSON object is no longer `ErrInvalidSignature`, and a non-string `typ` is accepted
- `/verify-keys` and the verify-keys parsers report a malformed `nonce`, such as `3.5`, `"42"` or `2147483648`, as `nonce-format` instead of `shape`, and an `iat` beyond `2^53−1` as `shape` instead of `stale`
- `/verify-keys` and the verify-keys parsers refuse what used to pass: a `crit` header or an `alg` spelled in another case (`signature`); a padded segment, or one with stray trailing bits or a line break (`shape`, `signature` in the signature segment); an `exp` that has passed or an `nbf` still ahead (`stale`). An undecodable signature segment is `signature` instead of `shape`, and a `null` payload `shape` instead of `iss-aud`. BoostX sends none of these
- The handlers answer `400` `invalid request body` for a body with anything after its JSON object, invalid UTF-8 or more than 64 KiB in all, and read a token sent under another spelling, such as `BoosterJWT`, as missing. BoostX's requests pass unchanged; check any client of your own that calls these endpoints, a test included
- `MountHandlers` panics on a prefix that does not start with `/`, a host-qualified one such as `example.com/api` included, or that holds `{`, `}`, a space or a tab: mount at the path of your API URL, and start the server once in staging before you upgrade
- The standalone handlers answer every method other than `POST` with `405`: a probe that sends `GET` to these paths gets `405` instead of `400`
- If you copied the hand-written `/verify-keys` handler from the examples, replace it with the new one or use `NewVerifyKeysHandler`
- A PEM block whose label is not one of the loader's own, such as `ECDSA PRIVATE KEY`, no longer loads, a `PRIVATE KEY` block must hold PKCS#8 and an `EC PRIVATE KEY` block SEC1, and header lines inside a block are refused. Load your key files once in staging before you upgrade
- A private key whose embedded public key does not match its private scalar, or is compressed, as `openssl ec -conv_form compressed` writes it, no longer loads. A file whose halves disagree is corrupt, and it used to load and sign as the scalar's key; rewrite a compressed one with `openssl ec -conv_form uncompressed`, and load your key files once in staging before you upgrade
- A private key file with bytes after the key, a PKCS#8 key of version 1 (OneAsymmetricKey) or with an extra field, or a SEC1 key with an unknown field or a curve other than P-256 inside PKCS#8, no longer loads. Keys written by OpenSSL, Go's `x509` or Node.js are unaffected; rewrite another with `openssl pkey -in key.pem -out partner_private.pem`
- `CreateVerifyKeysRequestToken` and `CreateVerifyKeysResponseToken` reject a `partnerID` that is not valid UTF-8 with `ErrInvalidClaim`. BoostX partner ids are ASCII, so only a test that signs a made-up id notices
- `MemoryKeyStore.RegisterWithPartnerPublicKeys` refuses an empty or `nil` list with `ErrInvalidPublicKey`: to register no partner public key, call `Register` with a `nil` one. An empty partner id is `ErrMissingClaim`, and an unusable key is refused at registration. A lookup for a role registered without a key matches `ErrInvalidPublicKey` or `ErrInvalidPrivateKey`; the handlers still answer it `500`
- `CreateGamePassToken` rejects a lowercase or mixed-case `Currency`, and any code that is not 3 or 4 letters `A`–`Z`, with `ErrInvalidClaim`: send `USD`, not `usd`. It also rejects an `Amount` below `0.01`
- `FloorX` and `PlayerX` return `NaN` for a `decimals` outside 2–6: pass the bet's `XDecimals`, which `CreateGamePassToken` keeps in that range
- `tokens.GamePass`, `tokens.ExtractGamePassClaims`, `tokens.ParseGamePassToken` and `handlers.GamePass` are deprecated: they check the signatures and the shape of the claims they read, not whether BoostX accepts the gamepass. They remain for tests
- A builder given an unusable private key reports `ErrInvalidPrivateKey` even when a parameter is also wrong, and a verify-keys parser given an unusable public key `ErrInvalidPublicKey`; `CreateVerifyKeysRequestToken`, `CreateVerifyKeysResponseToken`, `ParseVerifyKeysRequestToken` and `ParseVerifyKeysResponseToken` used to report the partner id first
- A client passed with `WithHTTPClient` whose `Timeout` is `0` gets a 30-second limit per `SubmitSettlement` attempt, and the limit now also covers the key store lookup: a key store must honour its context
- Treat every `SubmitSettlement` error as not delivered yet, whatever its status: send the same params again with a backoff, for example over 3 days, and alert if BoostX has still not accepted them. A `4xx` can come from a BoostX release that a fix undoes, and re-sending under the same `Version` is a no-op once BoostX holds it. The README's Submitting Settlements section shows the pattern and how to read each status when you diagnose an alert

### Improvements
- The README states the rule for the X of a round sent again: after a re-entry that changed `X`, the new one applies, except to a `final: true` regular round sent again, which keeps the one it was first sent with
- The README and godoc say that amounts are in major units and that `X` is your own coefficient before the boost, that `User` and `Bet` must not contain `:`, that key stores match the partner id byte for byte, that `CheckBet` answers `(false, nil)` for an unknown bet, and that the `MountHandlers` prefix is a URL path; the Quick Start checks every error, and the settlement section builds params once and queues params, not tokens
- Pin the GID signature test vector published in the partner docs
- The README and godoc give the order of the `/verify-keys` checks, and call `CreateVerifyKeysRequestToken` and `ParseVerifyKeysResponseToken` test aids: with `maxSkew` `0`, the response parser accepts no response BoostX would refuse at that moment
- The README and godoc say that a store wrapping another must forward `CheckBet`, or `/check-bet` is not registered, and `PartnerPublicKeys`, or only the current partner key verifies; and that the API URL should have no doubled slash, with the cleaned prefix to mount until it is fixed

## v0.11.2

### New Features
- Add `PlayerX(xBase, boost, decimals)` to the root `boostx` package and `boostx/tokens`. It returns the X the player saw for a Booster token's `boost`: `xBase` is floored to `decimals` places first, as BoostX floors `xrange.init` on receipt, then boosted and floored again. With `xBase` `1.857`, `boost` `1.5` and two decimals the player saw `2.27`, while flooring only the boosted value gives `2.28`. A `decimals` of `0`, an unset `XDecimals`, floors to the default `2`. `TestPlayerX_BoostXVectors` pins it against `boostx/tokens/testdata/player-x.json`, golden vectors generated by BoostX's implementation, many with an off-grid `xBase`
- Add `FloorX(x, decimals)`, the flooring step alone, to the root `boostx` package and `boostx/tokens`. It floors by the rule BoostX applies — the scaled value is first rounded to 15 significant digits — where a plain `math.Floor(x*100)/100` lands one step lower in some rounds: `1 + (14.95 − 1) × 1.2` shows as `17.74` and floors that way to `17.73`. `TestFloorX_BoostXVectors` pins it against `boostx/tokens/testdata/floor-x.json`, golden vectors generated by BoostX's implementation

### Bug Fixes
- Omit `xrange.min` and `xrange.max` from the GamePass when `XMin`/`XMax` are left at `0`, so BoostX applies its defaults, `1.1` and `200`. They were sent as `"min": 0, "max": 0`, which BoostX reads as bounds and refuses with `400 INVALID_PARAMS`, so a game whose bounds were not both set explicitly never started. A non-zero bound is sent as before
- Reject a GamePass `Amount` of `0` with `ErrInvalidClaim`, an `Amount` left at its zero value included. Since 2026-10-27 a stake must be greater than `0`: BoostX refuses a gamepass whose stake is `0` with `400 INVALID_PARAMS` on every entry, so the game does not open. A negative or non-finite `Amount` was already rejected
- Compute `CalculateFinalCoefficient` without fused multiply-add. Where Go fuses `1 + (x−1)*boost` into one instruction, arm64 among them, the raw X could differ from BoostX's in the last bit

### Improvements
- Document the replay rule on `BetStoreUpdater.SetBoost` and in the README: the SDK verifies signatures but does not reject replays, so `SetBoost` applies only a round above the last one applied for the bet and returns `nil` (`200`) without changing anything for any other. The `examples/server` bet store now follows it — keyed by partner, user and bet, with the check and the write under one lock — and no longer gives its two partner ids the same bet id
- Describe `CreateGamePassToken` in its godoc and the README as the call to make when the player opens the game, not a testing helper, and say in the README to set `XMax` when your own limits cap X below `200`

## v0.11.1

### Improvements
- Document that BoostX accepts a GamePassJWT only within 300 seconds of its `iat`, and only at the moment the game is opened, so `CreateGamePassToken` must be called when the player opens the game rather than ahead of time. The check is two-sided, so hosts calling it need synced clocks. No API or behaviour change

## v0.11.0

### New Features
- Re-export `ErrUnknownPartner` from the root `boostx` package. Custom key stores wrap it for a partner_id they do not serve to opt into the handlers' 400 mapping; it was previously reachable only via the `boostx/keys` subpackage

### Improvements
- Report a key-store unknown-partner failure on `/verify-keys` as the `iss-aud` reason (`invalid verifyKeysJWT: iss-aud (unknown partner "<id>")`) instead of a bare `unknown partner` 400. The request's `aud` naming a partner the deployment does not serve is an id mismatch, not a key failure, and key verification now attributes it to the partner-id configuration
- Name the offending id in key-lookup rejections across all handlers: `unknown partner "<id>"` instead of `unknown partner`, so a deployment registered under a different id can see from its own responses which id BoostX actually sent
- Document that `SettlementParams.Partner` and `GamePassParams.Partner` must be the BoostX-assigned partner id — the same value inbound tokens carry in `gid.partner`, not an internal id — and that key-store implementations must reject ids they do not serve rather than fall back to a default key set: an unkeyed single-tenant store passes every inbound check under any id and hides the mismatch until outbound calls are rejected. The README shows the explicit id check a custom single-tenant store needs

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
