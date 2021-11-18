package permissions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/ONSdigital/log.go/v2/log"
)

// package level constants
const (
	bundlerEndpoint = "%s/v1/permissions-bundle"
)

// Compiler check that the APIClient complies with the Store interface
var _ Store = (*APIClient)(nil)

// HTTPClient is the interface that defines a client for making HTTP requests
type HTTPClient interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// APIClient implementation of permissions.Store that gets permission data from the permissions API
type APIClient struct {
	host    string
	httpCli HTTPClient
	backoffSchedule []time.Duration
}

// NewAPIClient constructs a new APIClient instance.
func NewAPIClient(host string, httpClient HTTPClient, backoffSchedule []time.Duration) *APIClient {
	return &APIClient{
		host:    host,
		httpCli: httpClient,
		backoffSchedule: backoffSchedule,
	}
}

// GetPermissionsBundle gets the permissions bundle data from the permissions API.
func (c *APIClient) GetPermissionsBundle(ctx context.Context) (Bundle, error) {
	// function vars
	var (
		permissions Bundle
		uri = fmt.Sprintf(bundlerEndpoint, c.host)
		bundlerError error
		resp *http.Response
		req *http.Request
		maxRetryLimit = len(c.backoffSchedule)-1
	)
	for retryCount, backOff := range c.backoffSchedule {
		req, bundlerError = http.NewRequest(http.MethodGet, uri, nil)
		if bundlerError != nil {
			break
		}

		resp, bundlerError = c.httpCli.Do(ctx, req)
		if bundlerError != nil {
			break
		}

		defer func() {
			if resp.Body != nil {
				resp.Body.Close()
			}
		}()
		
		//check returned status and take appropriate action
		if resp.StatusCode != http.StatusOK {
			// if we've reached the last retry, set retryAllowed to false, error and break from loop
			if retryCount == maxRetryLimit {
				bundlerError = errors.New("bundler data not successfully retrieved from service - max retries reached ["+strconv.Itoa(maxRetryLimit)+"] - final response: "+strconv.Itoa(resp.StatusCode))
				break
			} else {
				log.Info(ctx, "unexpected status returned from the permissions api permissions-bundle endpoint: %s - retrying...", log.Data{"response": resp.Status})
			}
		} else {
			permissions, bundlerError = getPermissionsBundleFromResponse(resp.Body)
			break
		}
		time.Sleep(backOff)
	}
	return permissions, bundlerError
}

func getPermissionsBundleFromResponse(reader io.Reader) (Bundle, error) {
	b, err := getResponseBytes(reader)
	if err != nil {
		return nil, err
	}

	var bundle Bundle

	if err := json.Unmarshal(b, &bundle); err != nil {
		return nil, ErrFailedToParsePermissionsResponse
	}

	return bundle, nil
}

func getResponseBytes(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, ErrGetPermissionsResponseBodyNil
	}

	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	if b == nil || len(b) == 0 {
		return nil, ErrGetPermissionsResponseBodyNil
	}

	return b, nil
}
