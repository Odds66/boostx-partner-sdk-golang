package client

import (
	"context"
	"fmt"

	"github.com/Odds66/boostx-partner-sdk-golang/boostx/tokens"
)

// settlementRequest is the JSON body sent to POST /api/integration/settlement.
type settlementRequest struct {
	SettlementJWT string `json:"settlementJWT"`
}

// SubmitSettlement creates a signed settlement JWT from the given params and
// sends it to the BoostX API. The signing key is resolved via the Client's
// KeyStore.
func (c *Client) SubmitSettlement(ctx context.Context, params tokens.SettlementParams) error {
	key, err := c.keys.PartnerPrivateKey(ctx, params.Partner, params.User, params.Bet)
	if err != nil {
		return fmt.Errorf("resolve settlement key: %w", err)
	}

	jwt, err := tokens.CreateSettlementToken(key, params)
	if err != nil {
		return fmt.Errorf("create settlement token: %w", err)
	}

	return c.doAPIRequest(ctx, "/api/integration/settlement", settlementRequest{
		SettlementJWT: jwt,
	}, nil)
}
