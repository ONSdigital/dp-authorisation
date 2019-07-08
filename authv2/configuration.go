package authv2

import "net/http"

const (
	CollectionIDHeader = "Collection-Id"
)

var (
	getRequestVars func(r *http.Request) map[string]string
	authoriser     Authoriser
	datasetIDKey   string
)

// Configure set up function for the authorisation pkg. Requires the datasetID parameter key, a function for getting
// request parameters and a PermissionsAuthenticator implementation
func Configure(DatasetIDKey string, GetRequestVarsFunc func(r *http.Request) map[string]string, Authoriser Authoriser) {
	datasetIDKey = DatasetIDKey
	getRequestVars = GetRequestVarsFunc
	authoriser = Authoriser
}
