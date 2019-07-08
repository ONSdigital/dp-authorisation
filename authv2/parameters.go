package authv2

import (
	"fmt"
	"net/http"

	"github.com/ONSdigital/go-ns/common"
)

// Parameters is a model encapsulating details about the authorisation request.
type Parameters interface {
	NewGetDatasetPermissionsRequest(host string) (*http.Request, error)
}

type UserParameters struct {
	UserToken    string
	CollectionID string
	DatasetID    string
}

type ServiceParameters struct {
	ServiceToken string
	DatasetID    string
}

// newUserParameters is a constructor function for creating a new Parameters object for a user auth request.
func newUserParameters(userToken string, collectionID string, datasetID string) Parameters {
	return &UserParameters{
		UserToken:    userToken,
		CollectionID: collectionID,
		DatasetID:    datasetID,
	}
}

// newUserParameters is a constructor function for creating a new Parameters object for a service account auth request.
func newServiceParameters(serviceToken string, datasetID string) Parameters {
	return &ServiceParameters{
		ServiceToken: serviceToken,
		DatasetID:    datasetID,
	}
}

// createUserDatasetPermissionsRequest create a new get user dataset permissions HTTP request.
func (params *UserParameters) NewGetDatasetPermissionsRequest(host string) (*http.Request, error) {
	if host == "" {
		return nil, hostRequiredButEmptyError
	}

	url := fmt.Sprintf(userDatasetPermissionsURL, host, params.DatasetID, params.CollectionID)
	httpRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, Error{
			Cause:   err,
			Status:  500,
			Message: "error creating new get permissions http request",
		}
	}

	httpRequest.Header.Set(common.FlorenceHeaderKey, params.UserToken)
	return httpRequest, nil
}

// createServiceDatasetPermissionsRequest create a new get service account dataset permissions HTTP request.
func (params *ServiceParameters) NewGetDatasetPermissionsRequest(host string) (*http.Request, error) {
	if host == "" {
		return nil, hostRequiredButEmptyError
	}

	url := fmt.Sprintf(serviceDatasetPermissionsURL, host, params.DatasetID)
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, Error{
			Cause:   err,
			Status:  500,
			Message: "error making get permissions http request",
		}
	}

	r.Header.Set(common.AuthHeaderKey, params.ServiceToken)
	return r, nil
}
