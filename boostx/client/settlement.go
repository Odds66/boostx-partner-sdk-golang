package client

import (
	"context"
	"fmt"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// settlementPath is the settlement endpoint, relative to the base URL.
const settlementPath = "/api/integration/settlement"

// settlementRequest is the JSON body sent to POST /api/integration/settlement.
type settlementRequest struct {
	SettlementJWT string `json:"settlementJWT"`
}

// SubmitSettlement creates a settlement JWT signed with the key the Client's
// KeyStore holds for params.Partner and sends it to the BoostX API in one
// attempt. It returns nil only for BoostX's acceptance. Any error, whatever it
// is, means the settlement is not delivered yet: send the same params again,
// with a backoff, until it returns nil, and alert if a window such as 3 days
// ends first.
//
// Within one bet, re-sending params.Version unchanged is a no-op once BoostX
// holds it; corrections go out under a strictly higher version.
func (c *Client) SubmitSettlement(ctx context.Context, params tokens.SettlementParams) error {
	key, err := c.keys.PartnerPrivateKey(ctx, params.Partner)
	if err != nil {
		return fmt.Errorf("resolve settlement key: %w", err)
	}

	jwt, err := tokens.CreateSettlementToken(key, params)
	if err != nil {
		return fmt.Errorf("create settlement token: %w", err)
	}

	return c.doAPIRequest(ctx, settlementPath, settlementRequest{
		SettlementJWT: jwt,
	})
}
