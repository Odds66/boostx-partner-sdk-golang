package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx"
)

// betKey identifies a bet by partner, user and bet id: a bet id alone is not
// unique across the partner_ids one server serves.
type betKey struct {
	Partner, User, Bet string
}

// StoredBet represents a bet stored in the bet store.
type StoredBet struct {
	Active  bool
	Booster *boostx.Booster // last applied round; nil before the first
}

// MemoryBetStore is a simple in-memory implementation of BetStoreUpdater.
type MemoryBetStore struct {
	mu   sync.Mutex
	bets map[betKey]*StoredBet
}

// NewMemoryBetStore creates a new in-memory bet store.
func NewMemoryBetStore() *MemoryBetStore {
	return &MemoryBetStore{
		bets: make(map[betKey]*StoredBet),
	}
}

// AddBet adds a bet to the store.
func (s *MemoryBetStore) AddBet(partner, user, bet string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bets[betKey{partner, user, bet}] = &StoredBet{Active: true}
}

// CheckBet returns true if bet is active.
// Implementing BetStoreChecker is optional — the /check-bet endpoint is only
// registered when the BetStoreUpdater also implements this method.
func (s *MemoryBetStore) CheckBet(ctx context.Context, gid *boostx.GID) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	bet, ok := s.bets[betKey{gid.Partner, gid.User, gid.Bet}]
	if !ok {
		return false, nil
	}
	return bet.Active, nil
}

// SetBoost applies a round's boost. A round at or below the last applied one is
// a replay: it returns nil (200) and changes nothing. The check and the write
// share one lock, so a late replay cannot overwrite a newer round.
func (s *MemoryBetStore) SetBoost(ctx context.Context, booster *boostx.Booster) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bet, ok := s.bets[betKey{booster.Partner, booster.User, booster.Bet}]
	if !ok {
		return fmt.Errorf("%w: bet not found: %s", boostx.ErrRoundRejected, booster.Bet)
	}
	if bet.Booster != nil && booster.Round <= bet.Booster.Round {
		return nil
	}

	bet.Booster = booster
	fmt.Printf("Stored boost for bet %s: round=%d, boost=%.2f, final=%v\n",
		booster.Bet, booster.Round, booster.Boost, booster.Final)

	return nil
}
