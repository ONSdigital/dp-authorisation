package authv2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ONSdigital/go-ns/common"
	. "github.com/smartystreets/goconvey/convey"
)

const (
	datasetID        = "datasetID"
	collectionID     = "collectionID"
	userAuthToken    = "userAuthToken"
	serviceAuthToken = "serviceAuthToken"
)

var (
	readPermissions = &Permissions{
		Read: true,
	}

	fullPermissions = &Permissions{
		Create: true,
		Read:   true,
		Update: true,
		Delete: true,
	}
)

func TestRequireDatasetPermissions_userRequests(t *testing.T) {

	Convey("given the caller has the required permissions", t, func() {
		getVarsFunc := getVarsFunc(map[string]string{"dataset_id": datasetID})

		clienterMock := getClienterMock(readPermissions, nil)

		verifierMock := getVerifierMock(nil)

		Configure("dataset_id", getVarsFunc, clienterMock, verifierMock)

		wrappedHandler := &HandlerMock{count: 0}

		requiredPermissions := readPermissions

		w := httptest.NewRecorder()
		r := getRequest(userAuthToken, "", collectionID)

		authHandler := RequireDatasetPermissions(requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			authHandler.ServeHTTP(w, r)

			Convey("then permissionsClient getCallerDatasetPermissions is called once with the expected params", func() {
				getPermissionsCaller := clienterMock.GetCallerDatasetPermissionsCalls()
				expectedParams := newUserDatasetParameters(userAuthToken, collectionID, datasetID)

				So(getPermissionsCaller, ShouldHaveLength, 1)
				So(getPermissionsCaller[0].Params, ShouldResemble, expectedParams)
			})

			Convey("and CheckAuthorisation is called once with the expected values", func() {
				calls := verifierMock.CheckAuthorisationCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].CallerPermissions, ShouldResemble, readPermissions)
				So(calls[0].RequiredPermissions, ShouldResemble, requiredPermissions)
			})

			Convey("and the endpoint is invoked", func() {
				So(wrappedHandler.count, ShouldEqual, 1)
			})
		})
	})

	Convey("given the caller does not have the required permissions", t, func() {
		getVarsFunc := getVarsFunc(map[string]string{"dataset_id": datasetID})

		clientMock := getClienterMock(nil, Error{
			Status:  401,
			Message: "caller not authorised",
		})

		verifierMock := getVerifierMock(nil)

		Configure("dataset_id", getVarsFunc, clientMock, verifierMock)

		requiredPermissions := readPermissions

		wrappedHandler := &HandlerMock{count: 0}

		w := httptest.NewRecorder()
		r := getRequest(userAuthToken, "", collectionID)

		authHandler := RequireDatasetPermissions(requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			authHandler.ServeHTTP(w, r)

			Convey("then permissionsClient getCallerDatasetPermissions is called once with the expected params", func() {
				calls := clientMock.GetCallerDatasetPermissionsCalls()
				expectedParams := newUserDatasetParameters(userAuthToken, collectionID, datasetID)

				So(calls, ShouldHaveLength, 1)
				So(calls[0].Params, ShouldResemble, expectedParams)
			})

			Convey("and CheckAuthorisation is never called", func() {
				So(verifierMock.CheckAuthorisationCalls(), ShouldHaveLength, 0)
			})

			Convey("and the wrapped handler is not called", func() {
				So(wrappedHandler.count, ShouldEqual, 0)
			})

			Convey("and the appropriate error status is returned", func() {
				So(w.Code, ShouldEqual, 401)
				So(w.Body.String(), ShouldEqual, "caller not authorised")
			})
		})
	})

	Convey("given CheckCallerDatasetPermissions unexpected error", t, func() {
		getVarsFunc := getVarsFunc(map[string]string{"dataset_id": datasetID})

		clientMock := getClienterMock(readPermissions, nil)

		verifierMock := getVerifierMock(errors.New("bork"))

		Configure("dataset_id", getVarsFunc, clientMock, verifierMock)

		requiredPermissions := readPermissions

		wrappedHandler := &HandlerMock{count: 0}

		w := httptest.NewRecorder()
		r := getRequest(userAuthToken, "", collectionID)

		authHandler := RequireDatasetPermissions(requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			authHandler.ServeHTTP(w, r)

			Convey("then permissionsClient getCallerDatasetPermissions is called once with the expected params", func() {
				expectedParams := newUserDatasetParameters(userAuthToken, collectionID, datasetID)

				calls := clientMock.GetCallerDatasetPermissionsCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Params, ShouldResemble, expectedParams)
			})

			Convey("and CheckAuthorisation is called once with the expected params", func() {
				calls := verifierMock.CheckAuthorisationCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].RequiredPermissions, ShouldResemble, readPermissions)
				So(calls[0].CallerPermissions, ShouldResemble, readPermissions)
			})

			Convey("and the wrapped handler is not called", func() {
				So(wrappedHandler.count, ShouldEqual, 0)
			})

			Convey("and the appropriate error status is returned", func() {
				So(w.Code, ShouldEqual, 500)
				So(w.Body.String(), ShouldEqual, "internal server error")
			})
		})
	})
}

func TestRequireDatasetPermissions_invalidRequest(t *testing.T) {
	Convey("given a request that does not contain either a user auth token or a service auth token", t, func() {
		getVarsFunc := getVarsFunc(map[string]string{"dataset_id": ""})

		clientMock := getClienterMock(nil, nil)

		verifierMock := getVerifierMock(nil)

		Configure("dataset_id", getVarsFunc, clientMock, verifierMock)

		requiredPermissions := &Permissions{Read: true}

		wrappedHandler := &HandlerMock{count: 0}

		w := httptest.NewRecorder()
		r := getRequest("", "", "")

		authHandler := RequireDatasetPermissions(requiredPermissions, wrappedHandler.handleFunc)

		Convey("when the request is received", func() {
			authHandler.ServeHTTP(w, r)

			Convey("then the expected error status is returned", func() {
				So(w.Code, ShouldEqual, noUserOrServiceAuthTokenProvidedError.Status)
				So(w.Body.String(), ShouldEqual, noUserOrServiceAuthTokenProvidedError.Message)
			})

			Convey("and permissions client is not called", func() {
				So(clientMock.GetCallerDatasetPermissionsCalls(), ShouldHaveLength, 0)
			})

			Convey("and permissions verifier is not called", func() {
				So(verifierMock.CheckAuthorisationCalls(), ShouldHaveLength, 0)
			})

			Convey("and the wrapped handler is not invoked", func() {
				So(wrappedHandler.count, ShouldEqual, 0)
			})
		})
	})
}

func TestRequireDatasetPermissions_serviceRequests(t *testing.T) {

	Convey("given the caller has the required permissions", t, func() {
		getVarsFunc := getVarsFunc(map[string]string{"dataset_id": datasetID})

		clientMock := getClienterMock(readPermissions, nil)

		verifierMock := getVerifierMock(nil)

		Configure("dataset_id", getVarsFunc, clientMock, verifierMock)

		requiredPermissions := &Permissions{Read: true}

		wrappedHandler := &HandlerMock{count: 0}

		w := httptest.NewRecorder()
		r := getRequest("", serviceAuthToken, collectionID)

		authHandler := RequireDatasetPermissions(requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			authHandler.ServeHTTP(w, r)

			Convey("then GetCallerDatasetPermissions is called once with the expected params", func() {
				expectedParams := newServiceParameters(serviceAuthToken, datasetID)

				calls := clientMock.GetCallerDatasetPermissionsCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Params, ShouldResemble, expectedParams)
			})

			Convey("and CheckAuthorisation is called once with the expected params", func() {
				calls := verifierMock.CheckAuthorisationCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].CallerPermissions, ShouldResemble, readPermissions)
				So(calls[0].RequiredPermissions, ShouldResemble, readPermissions)
			})

			Convey("and the wrapped handler is invoked", func() {
				So(wrappedHandler.count, ShouldEqual, 1)
			})
		})
	})

	Convey("given the caller does not have the required permissions", t, func() {
		getVarsFunc := getVarsFunc(map[string]string{"dataset_id": datasetID})

		clientMock := getClienterMock(readPermissions, nil)

		verifierMock := getVerifierMock(checkAuthorisationForbiddenError)

		Configure("dataset_id", getVarsFunc, clientMock, verifierMock)

		requiredPermissions := &Permissions{Read: true}

		wrappedHandler := &HandlerMock{count: 0}

		w := httptest.NewRecorder()
		r := getRequest("", serviceAuthToken, collectionID)

		authHandler := RequireDatasetPermissions(requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			authHandler.ServeHTTP(w, r)

			Convey("then GetCallerDatasetPermissions is called once with the expected params", func() {
				expectedParams := newServiceParameters(serviceAuthToken, datasetID)

				calls := clientMock.GetCallerDatasetPermissionsCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Params, ShouldResemble, expectedParams)
			})

			Convey("and CheckAuthorisation is called once with the expected params", func() {
				calls := verifierMock.CheckAuthorisationCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].CallerPermissions, ShouldResemble, readPermissions)
				So(calls[0].RequiredPermissions, ShouldResemble, readPermissions)
			})

			Convey("and the wrapped handler is not called", func() {
				So(wrappedHandler.count, ShouldEqual, 0)
			})

			Convey("and the appropriate error status is returned", func() {
				So(w.Code, ShouldEqual, checkAuthorisationForbiddenError.Status)
				So(w.Body.String(), ShouldEqual, checkAuthorisationForbiddenError.Message)
			})
		})
	})

	Convey("given GetCallerPermissions unexpected error", t, func() {
		getVarsFunc := getVarsFunc(map[string]string{"dataset_id": datasetID})

		clientMock := getClienterMock(nil, errors.New("bork"))

		verifierMock := getVerifierMock(nil)

		Configure("dataset_id", getVarsFunc, clientMock, verifierMock)

		requiredPermissions := &Permissions{Read: true}

		wrappedHandler := &HandlerMock{count: 0}

		w := httptest.NewRecorder()
		r := getRequest("", serviceAuthToken, collectionID)

		authHandler := RequireDatasetPermissions(requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			authHandler.ServeHTTP(w, r)

			Convey("then GetCallerPermissions is called once with the expected params", func() {
				expectedParams := newServiceParameters(serviceAuthToken, datasetID)

				calls := clientMock.GetCallerDatasetPermissionsCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Params, ShouldResemble, expectedParams)
			})

			Convey("and CheckAuthorisation is not called", func() {
				So(verifierMock.CheckAuthorisationCalls(), ShouldHaveLength, 0)
			})

			Convey("and the wrapped handler is not called", func() {
				So(wrappedHandler.count, ShouldEqual, 0)
			})

			Convey("and the appropriate error status is returned", func() {
				So(w.Code, ShouldEqual, 500)
				So(w.Body.String(), ShouldEqual, "internal server error")
			})
		})
	})
}

func getRequest(userAuthToken, serviceAuthToken, collectionID string) *http.Request {
	r, err := http.NewRequest("GET", "http://localhost", nil)
	So(err, ShouldBeNil)
	r.Header.Set(common.FlorenceHeaderKey, userAuthToken)
	r.Header.Set(CollectionIDHeader, collectionID)
	r.Header.Set(common.AuthHeaderKey, serviceAuthToken)
	return r
}

func getClienterMock(p *Permissions, err error) *ClienterMock {
	return &ClienterMock{
		GetCallerDatasetPermissionsFunc: func(ctx context.Context, params Parameters) (permissions *Permissions, e error) {
			return p, err
		},
	}
}

func getVerifierMock(err error) *VerifierMock {
	return &VerifierMock{
		CheckAuthorisationFunc: func(ctx context.Context, callerPermissions *Permissions, requiredPermissions *Permissions) error {
			return err
		},
	}
}

func getVarsFunc(vars map[string]string) func(r *http.Request) map[string]string {
	return func(r *http.Request) map[string]string {
		return vars
	}
}
