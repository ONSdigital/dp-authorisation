package authv2

import (
	"context"
	"net/http"
)

//go:generate moq -out generated_mocks.go -pkg authv2 . Clienter Verifier

const (
	CollectionIDHeader = "Collection-Id"
)

var (
	getRequestVars      func(r *http.Request) map[string]string
	permissionsCli      Clienter
	permissionsVerifier Verifier
	datasetIDKey        string
)

type GetRequestVarsFunc func(r *http.Request) map[string]string

type HTTPClienter interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

type Clienter interface {
	GetCallerPermissions(ctx context.Context, params Parameters) (callerPermissions *Permissions, err error)
}

type Verifier interface {
	CheckPermissionsRequirementsSatisfied(ctx context.Context, callerPermissions *Permissions, requiredPermissions *Permissions) error
}

// Configure set up function for the authorisation pkg. Requires the datasetID parameter key, a function for getting
// request parameters and a PermissionsAuthenticator implementation
func Configure(DatasetIDKey string, GetRequestVarsFunc GetRequestVarsFunc, PermissionsClient Clienter, PermissionsVerifier Verifier) {
	datasetIDKey = DatasetIDKey
	getRequestVars = GetRequestVarsFunc
	permissionsCli = PermissionsClient
	permissionsVerifier = PermissionsVerifier
}
