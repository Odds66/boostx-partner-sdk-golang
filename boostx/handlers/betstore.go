package handlers

import (
	"context"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// BetStoreUpdater is implemented by the partner to handle bet operations.
// Only SetBoost is required. To enable the optional /checkBet endpoint,
// also implement BetStoreChecker.
type BetStoreUpdater interface {
	// SetBoost stores the boost update, returns error if validation fails
	SetBoost(ctx context.Context, boost *tokens.Boost) error
}

// BetStoreChecker is an optional interface. If the BetStoreUpdater also implements
// BetStoreChecker, the /checkBet endpoint is registered automatically.
// This endpoint is only called by BoostX when enabled for your integration.
type BetStoreChecker interface {
	// CheckBet returns true if bet is active
	CheckBet(ctx context.Context, identity *tokens.Identity) (active bool, err error)
}

// Re-export types for convenience.
type (
	Identity = tokens.Identity
	GamePass = tokens.GamePass
	Boost    = tokens.Boost
)
