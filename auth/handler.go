package auth

import (
	"context"
	"net/http"

	"github.com/ONSdigital/dp-permissions/permissions"
	"github.com/ONSdigital/go-ns/common"
	"github.com/ONSdigital/log.go/log"
)

//go:generate moq -out generated_auth_mocks.go -pkg auth . Authenticator

const (
	CollectionIDHeader = "Collection-Id"
)

var (
	getRequestVars func(r *http.Request) map[string]string
	authenticator  Authenticator
	datasetIDKey   string
)

// Configure set up function for the auth pkg. Requires the datasetID parameter key, a function for getting request
// parameters and a PermissionsAuthenticator implementation
func Configure(DatasetIDKey string, GetRequestVarsFunc func(r *http.Request) map[string]string, Authenticator Authenticator) {
	datasetIDKey = DatasetIDKey
	getRequestVars = GetRequestVarsFunc
	authenticator = Authenticator
}

type Authenticator interface {
	Vet(ctx context.Context, required permissions.CRUD, serviceToken string, userToken string, collectionID string, datasetID string) error
}

// Require is a http.HandlerFunc that verifies the caller holds the required permissions for the wrapped
// http.HandlerFunc If the caller has all of the required permissions then the request will continue to the wrapped
// handlerFunc. If the caller does not have all the required permissions then the the request is rejected with the
// appropriate http status and the wrapped handler is not invoked. If there is an error whilst attempting to check the
// callers permissions then a 500 status is returned and the wrapped handler is not invoked.
func Require(required permissions.CRUD, endpoint func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logD := log.Data{"requested_uri": r.URL.RequestURI()}

		serviceAuthToken := r.Header.Get(common.AuthHeaderKey)
		userAuthToken := r.Header.Get(common.FlorenceHeaderKey)
		collectionID := r.Header.Get(CollectionIDHeader)
		datasetID := getRequestVars(r)[datasetIDKey]

		err := authenticator.Vet(r.Context(), required, serviceAuthToken, userAuthToken, collectionID, datasetID)
		if err != nil {
			handleVetError(r.Context(), err, w, logD)
			return
		}

		log.Event(r.Context(), "endpoint permissions requirements met by caller", logD)
		endpoint(w, r)
	})
}

func handleVetError(ctx context.Context, err error, w http.ResponseWriter, logD log.Data) {
	permErr, ok := err.(permissions.Error)
	if ok {
		writeErr(ctx, w, permErr.Status, permErr.Message, logD)
		return
	}
	writeErr(ctx, w, 500, "internal server error", logD)
}

func writeErr(ctx context.Context, w http.ResponseWriter, status int, body string, logD log.Data) {
	w.WriteHeader(status)
	b := []byte(body)
	_, wErr := w.Write(b)
	if wErr != nil {
		w.WriteHeader(500)
		logD["original_err_body"] = body
		logD["original_err_status"] = status

		log.Event(ctx, "internal server error failed writing permissions error to response", log.Error(wErr), logD)
		return
	}
}
