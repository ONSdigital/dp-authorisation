package identityclient

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ONSdigital/dp-authorisation/v2/jwt"
	health "github.com/ONSdigital/dp-healthcheck/healthcheck"
	"github.com/ONSdigital/log.go/v2/log"

	dphttp "github.com/ONSdigital/dp-net/v2/http"
)

// contains default dp-net client settings
const (
	retryTime                = 1
	timeoutTime              = 10
	dialTimeoutTime          = 5
	tlsTimeoutTime           = 5
	maxIdleConns             = 10
	idleTimeoutTime          = 30
	jwtKeyRequestError       = "jwt keys request error"
	jwtKeyRequestOK          = "jwt keys request ok"
	identityRequestError     = "identity service request failed"
	identityHealthStateError = "Error updating state during authorisation identity client healthcheck"
	identityServiceJWTKeys   = "/v1/jwt-keys"
)

// IdentityInterface interface contains one method
//
//go:generate moq -out mock/identity_client.go -pkg mock . IdentityInterface
type IdentityInterface interface {
	Get(ctx context.Context, url string) (*http.Response, error)
}

// IdentityClient contains identity client handler
type IdentityClient struct {
	Client,
	BasicClient IdentityInterface
	JWTKeys          map[string]string
	IdentityEndpoint string
	CognitoRSAParser *jwt.CognitoRSAParser
}

// NewIdentityClient identity client constructor
func NewIdentityClient(identityEndpoint string, maxRetries int) (*IdentityClient, error) {
	return &IdentityClient{
		Client: &dphttp.Client{
			MaxRetries: maxRetries,
			RetryTime:  retryTime * time.Second,
			HTTPClient: &http.Client{
				Timeout: timeoutTime * time.Second,
				Transport: &http.Transport{
					DialContext: (&net.Dialer{
						Timeout: dialTimeoutTime * time.Second,
					}).DialContext,
					TLSHandshakeTimeout: tlsTimeoutTime * time.Second,
					MaxIdleConns:        maxIdleConns,
					IdleConnTimeout:     idleTimeoutTime * time.Second,
				},
			},
		},
		BasicClient:      dphttp.NewClient(),
		JWTKeys:          nil,
		IdentityEndpoint: identityEndpoint + identityServiceJWTKeys,
	}, nil
}

// Get wrapper for dp-net Get
func (c *IdentityClient) Get(ctx context.Context) (*http.Response, error) {
	identityResponse, err := c.Client.Get(ctx, c.IdentityEndpoint)
	if err != nil {
		log.Error(context.Background(), identityRequestError, err)
	}
	return identityResponse, err
}

// basicGet wrapper for dp-net Get
func (c *IdentityClient) basicGet(ctx context.Context) (*http.Response, error) {
	return c.BasicClient.Get(ctx, c.IdentityEndpoint)
}

// IdentityHealthCheck reports on status of jwt keys request against identity service
func (c *IdentityClient) IdentityHealthCheck(ctx context.Context, state *health.CheckState) error {
	if c.JWTKeys == nil {
		// attempt a new request on fail
		identityResponse, err := c.basicGet(ctx)
		if err != nil {
			if stateErr := state.Update(health.StatusCritical, jwtKeyRequestError, http.StatusInternalServerError); stateErr != nil {
				log.Error(context.Background(), identityHealthStateError, stateErr)
			}
			return err
		} else {
			err = c.unmarshalIdentityResponse(identityResponse.Body)
			if err != nil {
				return err
			}
			c.CognitoRSAParser, err = jwt.NewCognitoRSAParser(c.JWTKeys)
			if err != nil {
				return err
			}
			if stateErr := state.Update(health.StatusOK, jwtKeyRequestOK, http.StatusOK); stateErr != nil {
				log.Error(context.Background(), identityHealthStateError, stateErr)
			}
			return nil
		}
	}
	if stateErr := state.Update(health.StatusOK, jwtKeyRequestOK, http.StatusOK); stateErr != nil {
		log.Error(context.Background(), identityHealthStateError, stateErr)
	}
	return nil
}

// GetJWTVerificationKeys gets the JWT verification keys - takes identity client as argument
func (c *IdentityClient) GetJWTVerificationKeys(ctx context.Context) error {
	identityResponse, _ := c.Get(ctx)
	if identityResponse != nil {
		err := c.unmarshalIdentityResponse(identityResponse.Body)
		if err != nil {
			return err
		}
	}
	return nil
}

// unmarshalIdentityResponse method to unmarshal Get response body
func (c *IdentityClient) unmarshalIdentityResponse(responseBody io.ReadCloser) error {
	body, err := io.ReadAll(responseBody)
	if err != nil {
		return err
	}
	err = json.Unmarshal(body, &c.JWTKeys)
	if err != nil {
		return err
	}
	return nil
}
