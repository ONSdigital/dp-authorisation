package permissions

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ONSdigital/go-ns/common"
	"github.com/ONSdigital/log.go/log"
	"github.com/pkg/errors"
)

const gerPermissionsURL = "%s?dataset_id=%s&collection_id=%s"

type HTTPClient interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// CRUD is a representation of permissions required by an endpoint or held by a user/service.
type CRUD struct {
	Create bool
	Read   bool
	Update bool
	Delete bool
}

type Checker struct {
	host string
	c    HTTPClient
}

func NewChecker(host string, httpClient HTTPClient) *Checker {
	return &Checker{
		host: host,
		c:    httpClient,
	}
}

func (c *Checker) Check(ctx context.Context, required CRUD, serviceToken string, userToken string, collectionID string, datasetID string) (int, error) {
	// TODO
	return 0, nil
}

func (c *Checker) getPermissionsRequest(serviceToken string, userToken string, collectionID string, datasetID string) (*http.Request, error) {
	if c.host == "" {
		return nil, errors.New("error creating permissions request host not configured")
	}

	url := fmt.Sprintf(gerPermissionsURL, c.host, datasetID, collectionID)
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	r.Header.Set(common.FlorenceHeaderKey, userToken)
	r.Header.Set(common.AuthHeaderKey, serviceToken)

	return r, nil
}

func (required *CRUD) Satisfied(ctx context.Context, caller *CRUD) bool {
	missingPermissions := make([]string, 0)

	if required.Create && !caller.Create {
		missingPermissions = append(missingPermissions, "CREATE")
	}
	if required.Read && !caller.Read {
		missingPermissions = append(missingPermissions, "READ")
	}
	if required.Update && !caller.Update {
		missingPermissions = append(missingPermissions, "UPDATE")
	}
	if required.Delete && !caller.Delete {
		missingPermissions = append(missingPermissions, "DELETE")
	}

	if len(missingPermissions) > 0 {
		log.Event(ctx, "caller does not have the required permission", log.Data{
			"required_permissions": required,
			"caller_permissions":   caller,
			"missing_permissions": missingPermissions,
		})
		return false
	}

	log.Event(ctx, "caller has permissions required required permission", log.Data{
		"required_permissions": required,
		"caller_permissions":   caller,
	})
	return true
}
