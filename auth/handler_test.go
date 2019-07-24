package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
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

		getPermsReq := httptest.NewRequest("GET", host, nil)
		requestBuilder := getGetPermissionsRequestBuilderMock(getPermsReq, nil)

		wrappedHandler := &HandlerMock{count: 0}

		requiredPermissions := readPermissions

		authHandler := NewHandler(requestBuilder, clienterMock, verifierMock)

		h := authHandler.Require(*requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			inboundReq := httptest.NewRequest("GET", host, nil)
			w := httptest.NewRecorder()

			h.ServeHTTP(w, inboundReq)

			Convey("then requestBuilder.NewPermissionsRequest is called 1 time", func() {
				calls := requestBuilder.NewPermissionsRequestCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Req, ShouldResemble, getPermsReq)

			})

			Convey("and permissionsClient GetPermissions is called once with the expected parameter", func() {
				calls := clienterMock.GetPermissionsCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].GetPermissionsRequest, ShouldResemble, getPermsReq)
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

		getPermsReq := httptest.NewRequest("GET", host, nil)
		requestBuilder := getGetPermissionsRequestBuilderMock(getPermsReq, nil)

		wrappedHandler := &HandlerMock{count: 0}

		requiredPermissions := readPermissions

		authHandler := NewHandler(requestBuilder, clienterMock, verifierMock)

		h := authHandler.Require(*requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			w := httptest.NewRecorder()
			inboundReq := httptest.NewRequest("GET", host, nil)

			h.ServeHTTP(w, inboundReq)

			Convey("then requestBuilder.NewPermissionsRequest is called 1 time", func() {
				calls := requestBuilder.NewPermissionsRequestCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Req, ShouldResemble, inboundReq)

			})

			Convey("and permissionsClient GetCallerPermissions is called once with the expected params", func() {
				calls := clienterMock.GetPermissionsCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].GetPermissionsRequest, ShouldResemble, getPermsReq)
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

	Convey("given requestBuilder.NewPermissionsRequest returns an error", t, func() {
		clienterMock := getClienterMock(readPermissions, nil)

		verifierMock := getVerifierMock(checkAuthorisationForbiddenError)

		expectedErr := errors.New("pop")

		requestBuilder := getGetPermissionsRequestBuilderMock(nil, expectedErr)

		wrappedHandler := &HandlerMock{count: 0}

		requiredPermissions := readPermissions

		authHandler := NewHandler(requestBuilder, clienterMock, verifierMock)

		h := authHandler.Require(*requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			w := httptest.NewRecorder()
			inboundReq := httptest.NewRequest("GET", host, nil)

			h.ServeHTTP(w, inboundReq)

			Convey("then requestBuilder.NewPermissionsRequest is called 1 time", func() {
				calls := requestBuilder.NewPermissionsRequestCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Req, ShouldResemble, inboundReq)

			})

			Convey("and permissionsClient GetPermissionsCalls is never called", func() {
				calls := clienterMock.GetPermissionsCalls()
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

	Convey("given permissionsClient GetPermissions returns an error", t, func() {
		clienterMock := getClienterMock(nil, errors.New("internal server error"))

		verifierMock := getVerifierMock(checkAuthorisationForbiddenError)

		getPermsReq := httptest.NewRequest("GET", host, nil)
		requestBuilder := getGetPermissionsRequestBuilderMock(getPermsReq, nil)

		wrappedHandler := &HandlerMock{count: 0}

		requiredPermissions := readPermissions

		authHandler := NewHandler(requestBuilder, clienterMock, verifierMock)
		h := authHandler.Require(*requiredPermissions, wrappedHandler.handleFunc)

		Convey("when a request is received", func() {
			w := httptest.NewRecorder()

			inboundReq := httptest.NewRequest("GET", host, nil)
			h.ServeHTTP(w, inboundReq)

			Convey("then requestBuilder.NewPermissionsRequest is called 1 time", func() {
				calls := requestBuilder.NewPermissionsRequestCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].Req, ShouldResemble, inboundReq)

			})

			Convey("and permissionsClient GetPermissions is called 1 time", func() {
				calls := clienterMock.GetPermissionsCalls()
				So(calls, ShouldHaveLength, 1)
				So(calls[0].GetPermissionsRequest, ShouldResemble, inboundReq)
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
		GetPermissionsFunc: func(ctx context.Context, r *http.Request) (*Permissions, error) {
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

func getGetPermissionsRequestBuilderMock(r *http.Request, err error) *GetPermissionsRequestBuilderMock {
	return &GetPermissionsRequestBuilderMock{
		NewPermissionsRequestFunc: func(req *http.Request) (*http.Request, error) {
			return r, err
		},
	}
}
