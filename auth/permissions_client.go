package auth

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	dphttp "github.com/ONSdigital/dp-net/v3/http"
)

const (
	Create permissionType = "CREATE"
	Read   permissionType = "READ"
	Update permissionType = "UPDATE"
	Delete permissionType = "DELETE"
)

var (
	userInstancePermissionsURL    = "%s/userInstancePermissions"
	serviceInstancePermissionsURL = "%s/serviceInstancePermissions"
	userDatasetPermissionsURL     = "%s/userDatasetPermissions?dataset_id=%s&collection_id=%s"
	serviceDatasetPermissionsURL  = "%s/serviceDatasetPermissions?dataset_id=%s"
)

type permissionType string

type errorEntity struct {
	Message string `json:"message"`
}

type permissionsResponseEntity struct {
	List []permissionType `json:"permissions"`
}

type Permissions struct {
	Create bool
	Read   bool
	Update bool
	Delete bool
}

// PermissionsClient implementation of Clienter - provides functionality for getting caller permissions from a
// Permissions API.
type PermissionsClient struct {
	host    string
	httpCli HTTPClienter
}

func DefaultPermissionsClient() *PermissionsClient {
	return &PermissionsClient{httpCli: dphttp.NewClient()}
}

// NewPermissionsClient construct a new PermissionsClient instance.
//   - host is the URL of the permissions API to call.
//   - httpClient is instance of HTTPClienter
func NewPermissionsClient(httpClient HTTPClienter) *PermissionsClient {
	return &PermissionsClient{httpCli: httpClient}
}

func (client *PermissionsClient) GetPermissions(ctx context.Context, getPermissionsRequest *http.Request) (*Permissions, error) {
	if getPermissionsRequest == nil {
		return nil, getPermissionsRequestNilError
	}

	resp, err := client.doGetPermissionsRequest(ctx, getPermissionsRequest)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, handleGetPermissionsErrorResponse(ctx, resp.Body, resp.StatusCode)
	}

	permissions, err := getPermissionsFromResponse(resp.Body)
	if err != nil {
		return nil, err
	}

	return permissions, nil
}

func (client *PermissionsClient) doGetPermissionsRequest(ctx context.Context, request *http.Request) (*http.Response, error) {
	if request == nil {
		return nil, getPermissionsRequestNilError
	}

	resp, err := client.httpCli.Do(ctx, request)
	if err != nil {
		return nil, Error{
			Status:  500,
			Message: "get permissions request returned an error",
			Cause:   err,
		}
	}
	return resp, err
}

func getPermissionsFromResponse(reader io.Reader) (*Permissions, error) {
	b, err := getResponseBytes(reader)
	if err != nil {
		return nil, err
	}

	entity, err := unmarshalPermissionsResponseEntity(b)
	if err != nil {
		return nil, err
	}

	return permissionsResponseEntityToPermissions(entity), nil
}

func getResponseBytes(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, getPermissionsResponseBodyNilError
	}

	b, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, Error{
			Status:  500,
			Message: "internal server error failed reading get permissions response body",
			Cause:   err,
		}
	}

	if b == nil || len(b) == 0 {
		return nil, getPermissionsResponseBodyNilError
	}

	return b, nil
}

func unmarshalPermissionsResponseEntity(b []byte) (*permissionsResponseEntity, error) {
	var entity permissionsResponseEntity

	if len(b) == 0 {
		return &entity, nil
	}

	if err := json.Unmarshal(b, &entity); err != nil {
		return nil, Error{
			Status:  500,
			Message: "internal server error failed marshalling permissions response entity",
			Cause:   err,
		}
	}
	return &entity, nil
}

func permissionsResponseEntityToPermissions(entity *permissionsResponseEntity) *Permissions {
	permissions := &Permissions{}

	if entity == nil || entity.List == nil {
		return permissions
	}

	for _, p := range entity.List {
		switch p {
		case Create:
			permissions.Create = true
		case Read:
			permissions.Read = true
		case Update:
			permissions.Update = true
		case Delete:
			permissions.Delete = true
		}
	}
	return permissions
}
