package zebedeeclient

import (
	"context"

	"github.com/ONSdigital/dp-api-clients-go/identity"
	dprequest "github.com/ONSdigital/dp-net/request"
)

type ZebedeeClient struct {
	client *identity.Client
}

// NewZebedeeIdentity creates a new zebedee identity client
func NewZebedeeClient(ZebedeeURL string) *ZebedeeClient {
	return &ZebedeeClient{
		client: identity.New(ZebedeeURL),
	}
}

// CheckTokenIdentity calls dp-api-clients-go/identity
func (z ZebedeeClient) CheckTokenIdentity(ctx context.Context, token string) (*dprequest.IdentityResponse, error) {
	return z.client.CheckTokenIdentity(ctx, token, 0)
}
