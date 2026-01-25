package handlers

import (
	"context"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// BetStore is implemented by the partner to handle bet operations.
type BetStore interface {
	// CheckBet returns true if bet is active
	CheckBet(ctx context.Context, identity *tokens.Identity) (active bool, err error)

	// GetBet returns bet info and optional result
	GetBet(ctx context.Context, identity *tokens.Identity) (*BetInfo, error)

	// SetBoost stores the boost update, returns error if validation fails
	SetBoost(ctx context.Context, boost *tokens.Boost) error
}

// Re-export types for convenience.
type (
	Identity  = tokens.Identity
	GamePass  = tokens.GamePass
	Boost     = tokens.Boost
	BetInfo   = tokens.BetInfo
	BetResult = tokens.BetResult
)
