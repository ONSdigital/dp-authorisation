package permissions

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/ONSdigital/go-ns/common"
)

// getPermissionsRequest create a new get permissions http request for the specified service/user/collection ID/dataset ID values.
func (p *Permissions) getPermissionsRequest(serviceToken string, userToken string, collectionID string, datasetID string) (*http.Request, error) {
	if p.host == "" {
		return nil, Error{
			Status:  500,
			Message: "error creating permissionsList request host not configured",
		}
	}

	url := fmt.Sprintf(gerPermissionsURL, p.host, datasetID, collectionID)
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, Error{
			Cause:   err,
			Status:  500,
			Message: "error making get permissions http request",
		}
	}

	r.Header.Set(common.FlorenceHeaderKey, userToken)
	r.Header.Set(common.AuthHeaderKey, serviceToken)

	return r, nil
}

// getErrorFromResponse handle get permission responses with a non 200 status code.
func getErrorFromResponse(resp *http.Response) error {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Error{
			Status:  500,
			Message: "internal server error failed reading get permissions error response body",
			Cause:   err,
		}
	}

	var entity errorEntity
	if err = json.Unmarshal(body, &entity); err != nil {
		return Error{
			Status:  500,
			Message: "internal server error failed unmarshalling get permissions error response body",
			Cause:   err,
		}
	}

	return Error{Status: resp.StatusCode, Message: entity.Message}
}

// unmarshalPermissions read the response body and unmarshall into a CRUD object
func unmarshalPermissions(reader io.Reader) (*CRUD, error) {
	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	var callerPerms callerPermissions
	if err = json.Unmarshal(b, &callerPerms); err != nil {
		return nil, err
	}

	perms := &CRUD{}
	for _, p := range callerPerms.List {
		switch p {
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
