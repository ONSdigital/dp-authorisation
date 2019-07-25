package auth

import (
	"fmt"
	"net/http"

	"github.com/ONSdigital/go-ns/common"
)

type PermissionsRequestBuilder struct {
	Host string
}

func NewPermissionsRequestBuilder(host string) GetPermissionsRequestBuilder {
	return &PermissionsRequestBuilder{Host: host}
}

func (builder *PermissionsRequestBuilder) NewPermissionsRequest(req *http.Request) (*http.Request, error) {
	if err := builder.checkConfiguration(); err != nil {
		return nil, err
	}

	if req == nil {
		return nil, requestRequiredButNilError
	}

	userAuthToken := req.Header.Get(common.FlorenceHeaderKey)
	serviceAuthToken := req.Header.Get(common.AuthHeaderKey)

	if userAuthToken == "" && serviceAuthToken == "" {
		return nil, noUserOrServiceAuthTokenProvidedError
	}

	if userAuthToken != "" {
		return builder.createUserPermissionsRequest(userAuthToken)
	}

	return builder.createServicePermissionsRequest(serviceAuthToken)
}

func (builder *PermissionsRequestBuilder) createUserPermissionsRequest(authToken string) (*http.Request, error) {
	url := fmt.Sprintf(userInstancePermissionsURL, builder.Host)
	getPermissionsRequest, err := createRequest(url)
	if err != nil {
		return nil, err
	}
	getPermissionsRequest.Header.Set(common.FlorenceHeaderKey, authToken)
	return getPermissionsRequest, nil
}

func (builder *PermissionsRequestBuilder) createServicePermissionsRequest(authToken string) (*http.Request, error) {
	url := fmt.Sprintf(serviceInstancePermissionsURL, builder.Host)
	getPermissionsRequest, err := createRequest(url)
	if err != nil {
		return nil, err
	}
	getPermissionsRequest.Header.Set(common.AuthHeaderKey, authToken)
	return getPermissionsRequest, nil
}

func (builder *PermissionsRequestBuilder) checkConfiguration() error {
	if builder.Host == "" {
		return Error{
			Status:  500,
			Message: "PermissionsRequestBuilder configuration invalid host required but was empty",
		}
	}
	return nil
}
