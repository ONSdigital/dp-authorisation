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
func handleErrorResponse(ctx context.Context, resp *http.Response, data log.Data) int {
	data["status"] = resp.StatusCode
	log.Event(ctx, "get permissions request returned a non 200 response status", data)

	entity, err := unmarshallErrorEntity(resp.Body)
	if err != nil {
		// If we cannot read the error body then this becomes an internal server error
		log.Event(ctx, "internal server error failed reading get permissions error response", data)
		return 500
	}

	data["response_body"] = entity
	log.Event(ctx, "get permissions request unsuccessful", data)
	return resp.StatusCode
}

// unmarshallErrorEntity read the response body and unmarshall it into an error entity object
func unmarshallErrorEntity(r io.Reader) (*errorEntity, error) {
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var entity errorEntity
	if err = json.Unmarshal(body, &entity); err != nil {
		return nil, err
	}
	return &entity, nil
}

// unmarshalPermissions read the response body and unmarshall into a CRUD object
func unmarshalPermissions(ctx context.Context, reader io.Reader) (*CRUD, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
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
