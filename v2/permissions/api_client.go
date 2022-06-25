package permissions

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
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
	host            string
	httpCli         HTTPClient
	backoffSchedule []time.Duration
}

// NewAPIClient constructs a new APIClient instance.
func NewAPIClient(host string, httpClient HTTPClient, backoffSchedule []time.Duration) *APIClient {
	return &APIClient{
		host:            host,
		httpCli:         httpClient,
		backoffSchedule: backoffSchedule,
	}
}

// GetPermissionsBundle gets the permissions bundle data from the permissions API.
func (c *APIClient) GetPermissionsBundle(ctx context.Context) (Bundle, error) {

	uri := fmt.Sprintf(bundlerEndpoint, c.host)

	log.Info(ctx, "GetPermissionsBundle: starting permissions bundle request", log.Data{"uri": uri})

	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		log.Info(ctx, "GetPermissionsBundle: error building new request", log.Data{"err": err.Error()})
		return nil, err
	}

	resp, err := c.httpCli.Do(ctx, req)
	if err != nil {
		log.Info(ctx, "GetPermissionsBundle: error executing request", log.Data{"err": err.Error()})
		return nil, err
	}

	defer func() {
		if resp.Body != nil {
			resp.Body.Close()
		}
	}()

	log.Info(ctx, "GetPermissionsBundle: request successfully executed", log.Data{"resp.StatusCode": resp.StatusCode})

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status returned from the permissions api permissions-bundle endpoint: %s", resp.Status)
	}

	permissions, err := getPermissionsBundleFromResponse(resp.Body)
	if err != nil {
		log.Info(ctx, "GetPermissionsBundle: error getting permissions bundle from response", log.Data{"err": err.Error()})
		return nil, err
	}

	log.Info(ctx, "GetPermissionsBundle: returning requested permissions to caller")

	return permissions, nil
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
