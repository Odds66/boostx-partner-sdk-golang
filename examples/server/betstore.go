package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx"
)

// StoredBet represents a bet stored in the bet store.
type StoredBet struct {
	BetID   string
	Active  bool
	Booster *boostx.Booster
}

// MemoryBetStore is a simple in-memory implementation of BetStoreUpdater.
type MemoryBetStore struct {
	mu   sync.RWMutex
	bets map[string]*StoredBet
}

// NewMemoryBetStore creates a new in-memory bet store.
func NewMemoryBetStore() *MemoryBetStore {
	return &MemoryBetStore{
		bets: make(map[string]*StoredBet),
	}
}

// AddBet adds a bet to the store.
func (s *MemoryBetStore) AddBet(betID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bets[betID] = &StoredBet{BetID: betID, Active: true}
}

// CheckBet returns true if bet is active.
// Implementing BetStoreChecker is optional — the /check-bet endpoint is only
// registered when the BetStoreUpdater also implements this method.
func (s *MemoryBetStore) CheckBet(ctx context.Context, gid *boostx.GID) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bet, ok := s.bets[gid.Bet]
	if !ok {
		return false, nil
	}
	return bet.Active, nil
}

// SetBoost stores the boost update.
func (s *MemoryBetStore) SetBoost(ctx context.Context, booster *boostx.Booster) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bet, ok := s.bets[booster.Bet]
	if !ok {
		return fmt.Errorf("bet not found: %s", booster.Bet)
	}

	bet.Booster = booster
	fmt.Printf("Stored boost for bet %s: round=%d, boost=%.2f, final=%v\n",
		booster.Bet, booster.Round, booster.Boost, booster.Final)

	return nil
}
