package client

import (
	"context"
	"fmt"
)

// settlementRequest is the JSON body sent to POST /api/integration/settlement.
type settlementRequest struct {
	SettlementJWT string `json:"settlementJWT"`
}

// SubmitSettlement sends a signed settlement JWT to the BoostX API.
// The JWT should be created using tokens.CreateSettlementToken.
func (c *Client) SubmitSettlement(ctx context.Context, settlementJWT string) error {
	if settlementJWT == "" {
		return fmt.Errorf("settlementJWT must not be empty")
	}

	return c.doAPIRequest(ctx, "/api/integration/settlement", settlementRequest{
		SettlementJWT: settlementJWT,
	}, nil)
}
