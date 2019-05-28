package permissions

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/ONSdigital/go-ns/common"
	"github.com/ONSdigital/log.go/log"
	"github.com/pkg/errors"
)

// getPermissionsRequest create a new get permissions http request for the specified service/user/collection ID/dataset ID values.
func (c *Checker) getPermissionsRequest(serviceToken string, userToken string, collectionID string, datasetID string) (*http.Request, error) {
	if c.host == "" {
		return nil, errors.New("error creating permissionsList request host not configured")
	}

	url := fmt.Sprintf(gerPermissionsURL, c.host, datasetID, collectionID)
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "error making get permissionsList request")
	}

	r.Header.Set(common.FlorenceHeaderKey, userToken)
	r.Header.Set(common.AuthHeaderKey, serviceToken)

	return r, nil
}

// handleErrorResponse handle get permission responses with a non 200 status code.
func handleErrorResponse(ctx context.Context, resp *http.Response, data log.Data) (int, error) {
	log.Event(ctx, "get permissions request returned a non 200 response status", data)

	message, err := getErrorResponse(resp.Body)
	if err != nil {
		return 0, errors.WithMessage(err, "error reading get permissions error response")
	}

	data["cause"] = message
	log.Event(ctx, "get permissions request successful", data)
	return resp.StatusCode, nil
}

// handleSuccessfulResponse handles successful (200 status) get permissions responses. Marshal the response body into
// the CRUD object and verify it satisfies the required permissions. If the caller has the required permissions returns
// status 200 else returns status 403,
func handleSuccessfulResponse(ctx context.Context, resp *http.Response, required *CRUD, data log.Data) (int, error) {
	log.Event(ctx, "get permissions request successful", data)

	callerPerms, err := unmarshalPermissions(resp.Body)
	if err != nil {
		return 0, err
	}

	if !required.Satisfied(ctx, callerPerms) {
		return 403, nil
	}
	return 200, nil
}

// getErrorResponse get the response entity for a non 200 status code.
func getErrorResponse(r io.Reader) (string, error) {
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// unmarshalPermissions unmarshall the get permissions response json into a CRUD object
func unmarshalPermissions(reader io.Reader) (*CRUD, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, errors.WithMessage(err, "error reading get permissions response body")
	}

	var p permissions
	if err = json.Unmarshal(b, &p); err != nil {
		return nil, err
	}

	perms := &CRUD{}
	for _, val := range p.Permissions {
		switch val {
		case Create:
			perms.Create = true
		case Read:
			perms.Read = true
		case Update:
			perms.Update = true
		case Delete:
			perms.Delete = true
		}
	}
	return perms, nil
}
