package zebedeeclient_test

import (
	"context"
	"testing"

	"github.com/ONSdigital/dp-api-clients-go/v2/identity"
	"github.com/ONSdigital/dp-authorisation/v2/zebedeeclient"
	dprequest "github.com/ONSdigital/dp-net/v2/request"

	"github.com/ONSdigital/dp-authorisation/v2/authorisationtest"

	. "github.com/smartystreets/goconvey/convey"
)

type Client struct {
	Client zebedeeclient.IdentityClient
}

func (c Client) CheckTokenIdentity(ctx context.Context, token string, tokenType identity.TokenType) (*dprequest.IdentityResponse, error) {
	return &dprequest.IdentityResponse{
		Identifier: "bob.monkhouse@bm.io",
	}, nil
}

func TestZebedeeClient(t *testing.T) {
	ctx := context.Background()
	Convey("Given a zebedee client instance created", t, func() {
		zc := zebedeeclient.ZebedeeClient{
			Client: Client{},
		}

		r, _ := zc.CheckTokenIdentity(ctx, authorisationtest.ZebedeeServiceToken)

		Convey("Response is as expected", func() {
			So(r.Identifier, ShouldEqual, "bob.monkhouse@bm.io")
		})
	})
}
