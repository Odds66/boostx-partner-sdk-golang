// Package handlers provides inbound HTTP handlers for the BoostX partner
// integration endpoints.
package handlers

import (
	"context"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// BetStoreUpdater is implemented by the partner to handle bet operations.
// Only SetBoost is required. To enable the optional /check-bet endpoint,
// also implement BetStoreChecker.
type BetStoreUpdater interface {
	// SetBoost applies a round only if it is above the last one applied for
	// the bet, else returns nil (200); the SDK does not filter replays.
	SetBoost(ctx context.Context, booster *tokens.Booster) error
}

// BetStoreChecker is an optional interface. If the BetStoreUpdater also implements
// BetStoreChecker, the /check-bet endpoint is registered automatically.
// This endpoint is only called by BoostX when enabled for your integration.
type BetStoreChecker interface {
	// CheckBet returns true if bet is active
	CheckBet(ctx context.Context, gid *tokens.GID) (active bool, err error)
}

// Re-export types for convenience.
type (
	GID      = tokens.GID
	GamePass = tokens.GamePass
	Booster  = tokens.Booster
)
