package tokens

// BetInfo contains bet metadata and optional result.
type BetInfo struct {
	BetTimestamp   int64      `json:"bet_timestamp"`
	EventName      string     `json:"event_name"`
	EventMarket    string     `json:"event_market"`
	EventSelection string     `json:"event_selection"`
	Result         *BetResult `json:"result,omitempty"` // nil if not played yet
}

// BetResult contains the bet outcome.
type BetResult struct {
	Won      bool    `json:"won"`
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
	Boost    float64 `json:"boost"`
	FinalX   float64 `json:"final_x"`
}
