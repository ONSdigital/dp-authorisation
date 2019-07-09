package authv2

import (
	"fmt"
	"net/http"

	"github.com/ONSdigital/go-ns/common"
)

type Parameters interface {
	NewGetDatasetPermissionsRequest(host string) (*http.Request, error)
}

type UserDatasetParameters struct {
	UserToken    string
	CollectionID string
	DatasetID    string
}

type ServiceDatasetParameters struct {
	ServiceToken string
	DatasetID    string
}

func createDatasetAuthorisationParameters(req *http.Request) (Parameters, error) {
	userAuthToken := req.Header.Get(common.FlorenceHeaderKey)
	serviceAuthToken := req.Header.Get(common.AuthHeaderKey)
	collectionID := req.Header.Get(CollectionIDHeader)
	datasetID := getRequestVars(req)[datasetIDKey]

	if userAuthToken != "" {
		return newUserDatasetParameters(userAuthToken, collectionID, datasetID), nil
	}

	if serviceAuthToken != "" {
		return newServiceParameters(serviceAuthToken, datasetID), nil
	}

	return nil, noUserOrServiceAuthTokenProvidedError
}

func newUserDatasetParameters(userToken string, collectionID string, datasetID string) Parameters {
	return &UserDatasetParameters{
		UserToken:    userToken,
		CollectionID: collectionID,
		DatasetID:    datasetID,
	}
}

func newServiceParameters(serviceToken string, datasetID string) Parameters {
	return &ServiceDatasetParameters{
		ServiceToken: serviceToken,
		DatasetID:    datasetID,
	}
}

func (params *UserDatasetParameters) NewGetDatasetPermissionsRequest(host string) (*http.Request, error) {
	if host == "" {
		return nil, hostRequiredButEmptyError
	}

	url := fmt.Sprintf(userDatasetPermissionsURL, host, params.DatasetID, params.CollectionID)
	httpRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, Error{
			Cause:   err,
			Status:  500,
			Message: "error creating new get user dataset permissions http request",
		}
	}

	httpRequest.Header.Set(common.FlorenceHeaderKey, params.UserToken)
	return httpRequest, nil
}

func (params *ServiceDatasetParameters) NewGetDatasetPermissionsRequest(host string) (*http.Request, error) {
	if host == "" {
		return nil, hostRequiredButEmptyError
	}

	url := fmt.Sprintf(serviceDatasetPermissionsURL, host, params.DatasetID)
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, Error{
			Cause:   err,
			Status:  500,
			Message: "error creating new get service dataset permissions http request",
		}
	}

	r.Header.Set(common.AuthHeaderKey, params.ServiceToken)
	return r, nil
}
