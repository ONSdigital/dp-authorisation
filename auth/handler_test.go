package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

const (
	datasetID     = "datasetID"
	collectionID  = "collectionID"
	userAuthToken = "userAuthToken"
)

var (
	readPermissions = &Permissions{
		Read: true,
	}
)

func TestRequirePermissions(t *testing.T) {
	host := "http://localhost:8080"

	Convey("given the authorisation is successful", t, func() {
		clienterMock := getClienterMock(readPermissions, nil)

		verifierMock := getVerifierMock(nil)

		expectedParams := &ParametersMock{}

		paramFactory := getParameterFactoryMock(expectedParams, nil)

		wrappedHandler := &HandlerMock{count: 0}

		requiredPermissions := readPermissions

		authHandler := NewHandler(paramFactory, clienterMock, verifierMock)

		h := authHandler.Require(*requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", host, nil)

			h.ServeHTTP(w, r)

			Convey("then parameterFactory.CreateParameters is called 1 time", func() {
				calls := paramFactory.CreateParametersCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Req, ShouldResemble, r)

			})

			Convey("and permissionsClient GetCallerPermissions is called once with the expected params", func() {
				calls := clienterMock.GetCallerPermissionsCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Params, ShouldResemble, expectedParams)
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

	Convey("given the authorisation is unsuccessful", t, func() {
		clienterMock := getClienterMock(readPermissions, nil)

		verifierMock := getVerifierMock(checkAuthorisationForbiddenError)

		expectedParams := &ParametersMock{}

		paramFactory := getParameterFactoryMock(expectedParams, nil)

		wrappedHandler := &HandlerMock{count: 0}

		requiredPermissions := readPermissions

		authHandler := NewHandler(paramFactory, clienterMock, verifierMock)

		h := authHandler.Require(*requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", host, nil)

			h.ServeHTTP(w, r)

			Convey("then parameterFactory.CreateParameters is called 1 time", func() {
				calls := paramFactory.CreateParametersCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Req, ShouldResemble, r)

			})

			Convey("and permissionsClient GetCallerPermissions is called once with the expected params", func() {
				calls := clienterMock.GetCallerPermissionsCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Params, ShouldResemble, expectedParams)
			})

			Convey("and CheckAuthorisation is called once with the expected values", func() {
				calls := verifierMock.CheckAuthorisationCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].CallerPermissions, ShouldResemble, readPermissions)
				So(calls[0].RequiredPermissions, ShouldResemble, requiredPermissions)
			})

			Convey("and the endpoint is not invoked", func() {
				So(wrappedHandler.count, ShouldEqual, 0)
			})
		})
	})

	Convey("given parameterFactory.CreateParameters returns an error", t, func() {
		clienterMock := getClienterMock(readPermissions, nil)

		verifierMock := getVerifierMock(checkAuthorisationForbiddenError)

		paramFactory := getParameterFactoryMock(nil, errors.New("internal server error"))

		wrappedHandler := &HandlerMock{count: 0}

		requiredPermissions := readPermissions


		authHandler := NewHandler(paramFactory, clienterMock, verifierMock)

		h := authHandler.Require(*requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", host, nil)

			h.ServeHTTP(w, r)

			Convey("then parameterFactory.CreateParameters is called 1 time", func() {
				calls := paramFactory.CreateParametersCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Req, ShouldResemble, r)

			})

			Convey("and permissionsClient GetCallerPermissions is never called", func() {
				calls := clienterMock.GetCallerPermissionsCalls()
				So(calls, ShouldHaveLength, 0)
			})

			Convey("and CheckAuthorisation is never called", func() {
				calls := verifierMock.CheckAuthorisationCalls()
				So(calls, ShouldHaveLength, 0)
			})

			Convey("and the endpoint is not invoked", func() {
				So(wrappedHandler.count, ShouldEqual, 0)
			})

			Convey("and the expected error status is returned", func() {
				So(w.Code, ShouldEqual, 500)
			})
		})
	})

	Convey("given permissionsClient GetCallerPermissions returns an error", t, func() {
		clienterMock := getClienterMock(nil, errors.New("internal server error"))

		verifierMock := getVerifierMock(checkAuthorisationForbiddenError)

		paramFactory := getParameterFactoryMock(&ParametersMock{}, nil)

		wrappedHandler := &HandlerMock{count: 0}

		requiredPermissions := readPermissions


		authHandler := NewHandler(paramFactory, clienterMock, verifierMock)
		h := authHandler.Require(*requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			w := httptest.NewRecorder()

			r := httptest.NewRequest("GET", host, nil)
			h.ServeHTTP(w, r)

			Convey("then parameterFactory.CreateParameters is called 1 time", func() {
				calls := paramFactory.CreateParametersCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Req, ShouldResemble, r)

			})

			Convey("and permissionsClient GetCallerPermissions is called 1 time", func() {
				calls := clienterMock.GetCallerPermissionsCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Params, ShouldResemble, &ParametersMock{})
			})

			Convey("and CheckAuthorisation is never called", func() {
				calls := verifierMock.CheckAuthorisationCalls()
				So(calls, ShouldHaveLength, 0)
			})

			Convey("and the endpoint is not invoked", func() {
				So(wrappedHandler.count, ShouldEqual, 0)
			})

			Convey("and the expected error status is returned", func() {
				So(w.Code, ShouldEqual, 500)
			})
		})
	})
}

func getClienterMock(p *Permissions, err error) *ClienterMock {
	return &ClienterMock{
		GetCallerPermissionsFunc: func(ctx context.Context, params Parameters) (permissions *Permissions, e error) {
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

func getParameterFactoryMock(p Parameters, err error) *ParameterFactoryMock {
	return &ParameterFactoryMock{
		CreateParametersFunc: func(req *http.Request) (Parameters, error) {
			return p, err
		},
	}
}
