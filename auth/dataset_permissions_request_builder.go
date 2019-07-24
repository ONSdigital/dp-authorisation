package auth

import (
	"fmt"
	"net/http"

	"github.com/ONSdigital/go-ns/common"
)

type DatasetPermissionsRequestBuilder struct {
	Host               string
	DatasetIDKey       string
	GetRequestVarsFunc func(r *http.Request) map[string]string
}

type parameters struct {
	userAuthToken    string
	serviceAuthToken string
	collectionID     string
	datasetID        string
}

// NewPermissionsRequest fulfilling the GetPermissionsRequestBuilder interface. Builds get user/service account
// dataset permissions requests.
//	req - is the inbound http.Request to generate the get permissions request from.
func (builder *DatasetPermissionsRequestBuilder) NewPermissionsRequest(req *http.Request) (*http.Request, error) {
	if err := builder.checkConfiguration(); err != nil {
		return nil, err
	}

	if req == nil {
		return nil, requestRequiredButNilError
	}

	parameters := builder.extractRequestParameters(req)
	if err := parameters.isValid(); err != nil {
		return nil, err
	}

	if parameters.isUserRequest() {
		return builder.createUserDatasetPermissionsRequest(parameters)
	}

	return builder.createServiceDatasetPermissionsRequest(parameters)
}

func (builder *DatasetPermissionsRequestBuilder) extractRequestParameters(req *http.Request) parameters {
	return parameters{
		userAuthToken:    req.Header.Get(common.FlorenceHeaderKey),
		serviceAuthToken: req.Header.Get(common.AuthHeaderKey),
		collectionID:     req.Header.Get(common.CollectionIDHeaderKey),
		datasetID:        builder.GetRequestVarsFunc(req)[builder.DatasetIDKey],
	}
}

func (builder *DatasetPermissionsRequestBuilder) createUserDatasetPermissionsRequest(params parameters) (*http.Request, error) {
	url := fmt.Sprintf(userDatasetPermissionsURL, builder.Host, params.datasetID, params.collectionID)
	getPermissionsReq, err := createRequest(url)
	if err != nil {
		return nil, err
	}

	getPermissionsReq.Header.Set(common.FlorenceHeaderKey, params.userAuthToken)
	return getPermissionsReq, nil
}

func (builder *DatasetPermissionsRequestBuilder) createServiceDatasetPermissionsRequest(params parameters) (*http.Request, error) {
	url := fmt.Sprintf(serviceDatasetPermissionsURL, builder.Host, params.datasetID)
	getPermissionsReq, err := createRequest(url)
	if err != nil {
		return nil, err
	}
	getPermissionsReq.Header.Set(common.AuthHeaderKey, params.serviceAuthToken)
	return getPermissionsReq, nil
}

func (builder *DatasetPermissionsRequestBuilder) checkConfiguration() error {
	if builder.Host == "" {
		return Error{
			Status:  500,
			Message: "DatasetPermissionsRequestBuilder configuration invalid host required but was empty",
		}
	}
	if builder.DatasetIDKey == "" {
		return Error{
			Status:  500,
			Message: "DatasetPermissionsRequestBuilder configuration invalid datasetID key required but was empty",
		}
	}
	if builder.GetRequestVarsFunc == nil {
		return Error{
			Status:  500,
			Message: "DatasetPermissionsRequestBuilder configuration invalid GetRequestVarsFunc required but was nil",
		}
	}
	return nil
}

func (p parameters) isValid() error {
	if p.userAuthToken == "" && p.serviceAuthToken == "" {
		return noUserOrServiceAuthTokenProvidedError
	}
	return nil
}

func (p parameters) isUserRequest() bool {
	return p.userAuthToken != ""
}

func createRequest(url string) (*http.Request, error) {
	httpRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, Error{
			Cause:   err,
			Status:  500,
			Message: "error creating get dataset permissions http request",
		}
	}
	return httpRequest, nil
}
