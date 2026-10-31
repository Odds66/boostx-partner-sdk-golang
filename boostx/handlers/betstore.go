// Package handlers provides inbound HTTP handlers for the BoostX partner
// integration endpoints.
package handlers

import (
	"context"
	"errors"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// BetStoreUpdater is implemented by the partner to handle bet operations.
// Only SetBoost is required. To enable the optional /check-bet endpoint,
// also implement BetStoreChecker.
type BetStoreUpdater interface {
	// SetBoost applies a round only if it is above the last one applied for
	// the bet, else returns nil (200); the SDK does not filter replays. Return
	// ErrRoundRejected for a round you will not apply (400), any other error on
	// a failure (500).
	SetBoost(ctx context.Context, booster *tokens.Booster) error
}

// BetStoreChecker is an optional interface. If the BetStoreUpdater also implements
// BetStoreChecker, the /check-bet endpoint is registered automatically.
// This endpoint is only called by BoostX when enabled for your integration.
type BetStoreChecker interface {
	// CheckBet reports whether the bet is active: false, nil for a bet you do
	// not know or no longer accept. Return an error only when you cannot check;
	// it is answered 500, which BoostX reads as no verdict.
	CheckBet(ctx context.Context, gid *tokens.GID) (active bool, err error)
}

// Re-export types for convenience.
type (
	GID      = tokens.GID
	GamePass = tokens.GamePass
	Booster  = tokens.Booster
)

// ErrRoundRejected is returned, wrapped or not, by SetBoost for a round it has
// not applied and will not apply; the handler answers 400 "round rejected".
var ErrRoundRejected = errors.New("round rejected")
