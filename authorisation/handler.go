package authorisation

import (
	"context"
	"net/http"

	"github.com/ONSdigital/go-ns/common"
	"github.com/ONSdigital/log.go/log"
)

//go:generate moq -out generated_auth_mocks.go -pkg authorisation . Authoriser

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

// Allow given a policy, service and or user token, a collection ID and dataset ID determined if the caller has the
// necessary permissions to perform the requested action.
type Authoriser interface {
	Allow(ctx context.Context, required Policy, serviceToken string, userToken string, collectionID string, datasetID string) error
}

// Check is an authorisation wrapper that decorates another http.HandlerFunc. The provided policy determines what
// permissions are required by the caller to be able to perform the requested action.
//
// If the caller has each of the required permissions then authorisation is successfully and the request is delegated to
// the wrapped handlerFunc. If the caller does not have the required permissions then authorisation is unsuccessfully.
// The request is rejected with the appropriate http status and the wrapped handlerFunc is not invoked. If there is
// an error whilst checking the caller's permissions then a 500 status is returned and the wrapped handlerFunc is not
// invoked.
func Check(required Policy, handlerFunc func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logD := log.Data{"requested_uri": r.URL.RequestURI()}

		serviceAuthToken := r.Header.Get(common.AuthHeaderKey)
		userAuthToken := r.Header.Get(common.FlorenceHeaderKey)
		collectionID := r.Header.Get(CollectionIDHeader)
		datasetID := getRequestVars(r)[datasetIDKey]

		err := authoriser.Allow(r.Context(), required, serviceAuthToken, userAuthToken, collectionID, datasetID)
		if err != nil {
			handleAuthoriseError(r.Context(), err, w, logD)
			return
		}

		log.Event(r.Context(), "caller authorised to perform requested action", logD)
		handlerFunc(w, r)
	})
}

func handleAuthoriseError(ctx context.Context, err error, w http.ResponseWriter, logD log.Data) {
	permErr, ok := err.(Error)
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
