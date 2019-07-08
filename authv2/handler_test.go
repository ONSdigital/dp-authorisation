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

func TestCheckDatasetPermissions_userRequests(t *testing.T) {

	Convey("given the caller has the required permissions", t, func() {
		getVarsFunc := getVarsFunc(map[string]string{"dataset_id": datasetID})

		authoriserMock := getAuthoriserMock(nil)

		Configure("dataset_id", getVarsFunc, authoriserMock)

		requiredPermissions := &Permissions{Read: true}

		wrappedHandler := &HandlerMock{count: 0}

		w := httptest.NewRecorder()
		r := getRequest(userAuthToken, "", collectionID)

		authHandler := CheckDatasetPermissions(requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			authHandler.ServeHTTP(w, r)

			Convey("then CheckCallerDatasetPermissions is called once with the expected params", func() {
				authoriserCalls := authoriserMock.CheckCallerDatasetPermissionsCalls()
				expectedParams := newUserParameters(userAuthToken, collectionID, datasetID)

				So(authoriserCalls, ShouldHaveLength, 1)
				So(authoriserCalls[0].Required, ShouldEqual, requiredPermissions)
				So(authoriserCalls[0].Params, ShouldResemble, expectedParams)
			})

			Convey("and the wrapped handler is invoked", func() {
				So(wrappedHandler.count, ShouldEqual, 1)
			})
		})
	})

	Convey("given the caller does not have the required permissions", t, func() {
		getVarsFunc := getVarsFunc(map[string]string{"dataset_id": datasetID})

		authoriserMock := getAuthoriserMock(Error{
			Status:  401,
			Message: "caller not authorised",
		})

		Configure("dataset_id", getVarsFunc, authoriserMock)

		requiredPermissions := &Permissions{Read: true}

		wrappedHandler := &HandlerMock{count: 0}

		w := httptest.NewRecorder()
		r := getRequest(userAuthToken, "", collectionID)

		authHandler := CheckDatasetPermissions(requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			authHandler.ServeHTTP(w, r)

			Convey("then CheckCallerDatasetPermissions is called once with the expected params", func() {
				authoriserCalls := authoriserMock.CheckCallerDatasetPermissionsCalls()
				expectedParams := newUserParameters(userAuthToken, collectionID, datasetID)

				So(authoriserCalls, ShouldHaveLength, 1)
				So(authoriserCalls[0].Required, ShouldEqual, requiredPermissions)
				So(authoriserCalls[0].Params, ShouldResemble, expectedParams)
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

		authoriserMock := getAuthoriserMock(errors.New("bork"))

		Configure("dataset_id", getVarsFunc, authoriserMock)

		requiredPermissions := &Permissions{Read: true}

		wrappedHandler := &HandlerMock{count: 0}

		w := httptest.NewRecorder()
		r := getRequest(userAuthToken, "", collectionID)

		authHandler := CheckDatasetPermissions(requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			authHandler.ServeHTTP(w, r)

			Convey("then CheckCallerDatasetPermissions is called once with the expected params", func() {
				authoriserCalls := authoriserMock.CheckCallerDatasetPermissionsCalls()
				expectedParams := newUserParameters(userAuthToken, collectionID, datasetID)

				So(authoriserCalls, ShouldHaveLength, 1)
				So(authoriserCalls[0].Required, ShouldEqual, requiredPermissions)
				So(authoriserCalls[0].Params, ShouldResemble, expectedParams)
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

func TestCheckDatasetPermissions_invalidRequest(t *testing.T) {
	Convey("given a request that does not contain either a user auth token or a service auth token", t, func() {
		getVarsFunc := getVarsFunc(map[string]string{"dataset_id": ""})

		authoriserMock := getAuthoriserMock(nil)

		Configure("dataset_id", getVarsFunc, authoriserMock)

		requiredPermissions := &Permissions{Read: true}

		wrappedHandler := &HandlerMock{count: 0}

		w := httptest.NewRecorder()
		r := getRequest("", "", "")

		authHandler := CheckDatasetPermissions(requiredPermissions, wrappedHandler.handleFunc)

		Convey("when the request is received", func() {
			authHandler.ServeHTTP(w, r)

			Convey("then the expected error status is returned", func() {
				So(w.Code, ShouldEqual, noUserOrServiceAuthTokenProvidedError.Status)
				So(w.Body.String(), ShouldEqual, noUserOrServiceAuthTokenProvidedError.Message)
			})

			Convey("and CheckCallerDatasetPermissions is not called", func() {
				So(authoriserMock.CheckCallerDatasetPermissionsCalls(), ShouldHaveLength, 0)
			})

			Convey("and the wrapped handler is not invoked", func() {
				So(wrappedHandler.count, ShouldEqual, 0)
			})
		})
	})
}

func TestCheckDatasetPermissions_serviceRequests(t *testing.T) {

	Convey("given the caller has the required permissions", t, func() {
		getVarsFunc := getVarsFunc(map[string]string{"dataset_id": datasetID})

		authoriserMock := getAuthoriserMock(nil)

		Configure("dataset_id", getVarsFunc, authoriserMock)

		requiredPermissions := &Permissions{Read: true}

		wrappedHandler := &HandlerMock{count: 0}

		w := httptest.NewRecorder()
		r := getRequest("", serviceAuthToken, collectionID)

		authHandler := CheckDatasetPermissions(requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			authHandler.ServeHTTP(w, r)

			Convey("then CheckCallerDatasetPermissions is called once with the expected params", func() {
				authoriserCalls := authoriserMock.CheckCallerDatasetPermissionsCalls()
				expectedParams := newServiceParameters(serviceAuthToken, datasetID)

				So(authoriserCalls, ShouldHaveLength, 1)
				So(authoriserCalls[0].Required, ShouldEqual, requiredPermissions)
				So(authoriserCalls[0].Params, ShouldResemble, expectedParams)
			})

			Convey("and the wrapped handler is invoked", func() {
				So(wrappedHandler.count, ShouldEqual, 1)
			})
		})
	})

	Convey("given the caller does not have the required permissions", t, func() {
		getVarsFunc := getVarsFunc(map[string]string{"dataset_id": datasetID})

		authoriserMock := getAuthoriserMock(Error{
			Status:  401,
			Message: "caller not authorised",
		})

		Configure("dataset_id", getVarsFunc, authoriserMock)

		requiredPermissions := &Permissions{Read: true}

		wrappedHandler := &HandlerMock{count: 0}

		w := httptest.NewRecorder()
		r := getRequest("", serviceAuthToken, collectionID)

		authHandler := CheckDatasetPermissions(requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			authHandler.ServeHTTP(w, r)

			Convey("then CheckCallerDatasetPermissions is called once with the expected params", func() {
				authoriserCalls := authoriserMock.CheckCallerDatasetPermissionsCalls()
				expectedParams := newServiceParameters(serviceAuthToken, datasetID)

				So(authoriserCalls, ShouldHaveLength, 1)
				So(authoriserCalls[0].Required, ShouldEqual, requiredPermissions)
				So(authoriserCalls[0].Params, ShouldResemble, expectedParams)
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

		authoriserMock := getAuthoriserMock(errors.New("bork"))

		Configure("dataset_id", getVarsFunc, authoriserMock)

		requiredPermissions := &Permissions{Read: true}

		wrappedHandler := &HandlerMock{count: 0}

		w := httptest.NewRecorder()
		r := getRequest("", serviceAuthToken, collectionID)

		authHandler := CheckDatasetPermissions(requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			authHandler.ServeHTTP(w, r)

			Convey("then CheckCallerDatasetPermissions is called once with the expected params", func() {
				authoriserCalls := authoriserMock.CheckCallerDatasetPermissionsCalls()
				expectedParams := newServiceParameters(serviceAuthToken, datasetID)

				So(authoriserCalls, ShouldHaveLength, 1)
				So(authoriserCalls[0].Required, ShouldEqual, requiredPermissions)
				So(authoriserCalls[0].Params, ShouldResemble, expectedParams)
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

func getAuthoriserMock(err error) *AuthoriserMock {
	return &AuthoriserMock{
		CheckCallerDatasetPermissionsFunc: func(ctx context.Context, required *Permissions, params *Parameters) error {
			return err
		},
	}
}

func getVarsFunc(vars map[string]string) func(r *http.Request) map[string]string {
	return func(r *http.Request) map[string]string {
		return vars
	}
}
