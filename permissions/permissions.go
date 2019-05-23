package permissions

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ONSdigital/go-ns/common"
	"github.com/pkg/errors"
)

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

func (c *Checker) Check(required CRUD, serviceToken string, userToken string, collectionID string, datasetID string) (int, error) {
	return 0, nil
}

func (c *Checker) getPermissionsRequest(serviceToken string, userToken string, collectionID string, datasetID string) (*http.Request, error) {
	if c.host == "" {
		return nil, errors.New("error creating permissions request host not configured")
	}

	url := fmt.Sprintf("%s?dataset_id=%s&collection_id=%s", c.host, datasetID, collectionID)
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	r.Header.Set(common.FlorenceHeaderKey, userToken)
	r.Header.Set(common.AuthHeaderKey, serviceToken)

	return r, nil
}

func (required *CRUD) Check(caller *CRUD) bool {
	return false
}
