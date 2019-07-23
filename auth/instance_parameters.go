package auth

import (
	"fmt"
	"net/http"

	"github.com/ONSdigital/go-ns/common"
)

type UserInstanceParameters struct {
	UserAuthToken string
}

type ServiceInstanceParameters struct {
	ServiceAuthToken string
}

type InstanceParameterFactory struct{}

func (f *InstanceParameterFactory) CreateParameters(req *http.Request) (Parameters, error) {
	if req == nil {
		return nil, requestRequiredButNilError
	}

	userAuthToken := req.Header.Get(common.FlorenceHeaderKey)
	serviceAuthToken := req.Header.Get(common.AuthHeaderKey)

	if userAuthToken == "" && serviceAuthToken == "" {
		return nil, noUserOrServiceAuthTokenProvidedError
	}

	if userAuthToken != "" {
		return &UserInstanceParameters{UserAuthToken: userAuthToken}, nil
	}

	return &ServiceInstanceParameters{ServiceAuthToken: serviceAuthToken}, nil
}

// CreateGetPermissionsRequest fulfilling the Parameters interface - creates a Permissions API request to get user
// instance permissions.
func (params *UserInstanceParameters) CreateGetPermissionsRequest(host string) (*http.Request, error) {
	if host == "" {
		return nil, hostRequiredButEmptyError
	}

	url := fmt.Sprintf(userInstancePermissionsURL, host)
	httpRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, Error{
			Cause:   err,
			Status:  500,
			Message: "error creating new get user dataset permissions http request",
		}
	}

	httpRequest.Header.Set(common.FlorenceHeaderKey, params.UserAuthToken)
	return httpRequest, nil
}

func (params *ServiceInstanceParameters) CreateGetPermissionsRequest(host string) (*http.Request, error) {
	if host == "" {
		return nil, requestRequiredButNilError
	}

	url := fmt.Sprintf(serviceInstancePermissionsURL, host)
	httpRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, Error{
			Cause:   err,
			Status:  500,
			Message: "error creating new get user dataset permissions http request",
		}
	}

	httpRequest.Header.Set(common.AuthHeaderKey, params.ServiceAuthToken)
	return httpRequest, nil
}
