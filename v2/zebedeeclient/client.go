package zebedeeclient

import (
	"context"

	"github.com/ONSdigital/dp-api-clients-go/v2/identity"
	dprequest "github.com/ONSdigital/dp-net/request"
)

// IdentityClient interface contains one method
type IdentityClient interface {
	CheckTokenIdentity(ctx context.Context, token string, tokenType identity.TokenType) (*dprequest.IdentityResponse, error)
}

// ZebedeeClient contains zebedee client handler
type ZebedeeClient struct {
	Client IdentityClient
}

// NewZebedeeIdentity creates a new zebedee identity client
func NewZebedeeClient(ZebedeeURL string) *ZebedeeClient {
	return &ZebedeeClient{
		Client: identity.New(ZebedeeURL),
	}
}

// CheckTokenIdentity calls dp-api-clients-go/identity
func (z ZebedeeClient) CheckTokenIdentity(ctx context.Context, token string) (*dprequest.IdentityResponse, error) {
	return z.Client.CheckTokenIdentity(ctx, token, 0)
}
