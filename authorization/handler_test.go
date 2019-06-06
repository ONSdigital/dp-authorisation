package authorization

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"context"

	"github.com/ONSdigital/dp-api-permissions/permissions"
	"github.com/ONSdigital/go-ns/common"
	"github.com/ONSdigital/log.go/log"
	"github.com/pkg/errors"
	. "github.com/smartystreets/goconvey/convey"
)

const (
	serviceAuthToken = "666"
	userAuthToken    = "667"
	collectionID     = "668"
	datasetID        = "669"
	datsetIDKey      = "dataset_id"
)

type handlerCalls struct {
	R *http.Request
	W http.ResponseWriter
}

// Scenario: Request from an authorized caller
// given an authorized caller
// when their request is received
// then the authorizer confirms the caller holds the required permissions
// and the request is allowed to continue
func TestRequire_CallerAuthorized(t *testing.T) {
	Convey("given an authorized caller", t, func() {
		authorizerMock := getAuthorizerMock(nil)

		Configure(datsetIDKey, getRequestVarsMoq(), authorizerMock)

		requiredPermissions := permissions.Policy{
			Create: true,
			Read:   true,
			Update: true,
			Delete: true,
		}

		handlerCalls := make([]handlerCalls, 0)
		handler := getHandlerMoq(&handlerCalls)

		authHandler := Handler(requiredPermissions, handler)

		req := getRequest(t)
		w := httptest.NewRecorder()

		Convey("when their request is received", func() {
			authHandler(w, req)

			Convey("then the authorizer confirms the caller holds the required permissions", func() {
				So(authorizerMock.AllowCalls(), ShouldHaveLength, 1)
				So(authorizerMock.AllowCalls()[0].Required, ShouldResemble, requiredPermissions)
				So(authorizerMock.AllowCalls()[0].ServiceToken, ShouldEqual, serviceAuthToken)
				So(authorizerMock.AllowCalls()[0].UserToken, ShouldEqual, userAuthToken)
				So(authorizerMock.AllowCalls()[0].CollectionID, ShouldEqual, collectionID)
				So(authorizerMock.AllowCalls()[0].DatasetID, ShouldEqual, datasetID)
			})

			Convey("and the request is allowed to continue", func() {
				So(handlerCalls, ShouldHaveLength, 1)
				So(handlerCalls[0].R, ShouldResemble, req)
				So(handlerCalls[0].W, ShouldResemble, w)
			})
		})
	})
}

// Scenario: Request from an unauthorized caller
// given an unauthorized caller
// when their request is received
// then the authorizer confirms the caller is not authorized to perform the requested action
// and a 401 response is returned
// and the request does not continue
func TestRequire_CallerNotAuthorized(t *testing.T) {
	Convey("given an unauthorized caller", t, func() {
		authorizerMock := getAuthorizerMock(permissions.Error{
			Message: "unauthorized",
			Status:  401,
		})

		Configure(datsetIDKey, getRequestVarsMoq(), authorizerMock)

		handlerCalls := make([]handlerCalls, 0)
		handler := getHandlerMoq(&handlerCalls)

		requiredPermissions := permissions.Policy{
			Create: false,
			Read:   true,
			Update: false,
			Delete: false,
		}
		authHandler := Handler(requiredPermissions, handler)

		req := getRequest(t)
		w := httptest.NewRecorder()

		Convey("when their request is received", func() {
			authHandler(w, req)

			Convey("then the authorizer confirms the caller is not authorized to perform the requested action", func() {
				So(authorizerMock.AllowCalls(), ShouldHaveLength, 1)
				So(authorizerMock.AllowCalls()[0].Required, ShouldResemble, requiredPermissions)
				So(authorizerMock.AllowCalls()[0].ServiceToken, ShouldEqual, serviceAuthToken)
				So(authorizerMock.AllowCalls()[0].UserToken, ShouldEqual, userAuthToken)
				So(authorizerMock.AllowCalls()[0].CollectionID, ShouldEqual, collectionID)
				So(authorizerMock.AllowCalls()[0].DatasetID, ShouldEqual, datasetID)
			})

			Convey("and a 401 response is returned", func() {
				So(w.Code, ShouldEqual, 401)
			})

			Convey("and the request does not continue", func() {
				So(handlerCalls, ShouldBeEmpty)
			})
		})
	})
}

// Scenario: checking caller permissions returns an error
// given permissions check returns an error
// when a request is received
// then the authorizer is called with the expected parameters
// and a 500 response is returned
// and the request does not continue
func TestRequire_CheckPermissionsError(t *testing.T) {
	Convey("given permissions check returns an error", t, func() {
		authorizerMock := getAuthorizerMock(errors.New("wubba lubba dub dub"))

		Configure(datsetIDKey, getRequestVarsMoq(), authorizerMock)

		handlerCalls := make([]handlerCalls, 0)
		handler := getHandlerMoq(&handlerCalls)

		requiredPermissions := permissions.Policy{
			Create: false,
			Read:   true,
			Update: false,
			Delete: false,
		}

		authHandler := Handler(requiredPermissions, handler)

		req, _ := http.NewRequest("GET", "/something", nil)
		req.Header.Set(common.AuthHeaderKey, serviceAuthToken)
		req.Header.Set(common.FlorenceHeaderKey, userAuthToken)
		req.Header.Set(CollectionIDHeader, collectionID)

		w := httptest.NewRecorder()

		Convey("when a request is received", func() {
			authHandler(w, req)

			Convey("then the authorizer is called with the expected parameters", func() {
				So(authorizerMock.AllowCalls(), ShouldHaveLength, 1)
				So(authorizerMock.AllowCalls()[0].Required, ShouldResemble, requiredPermissions)
				So(authorizerMock.AllowCalls()[0].ServiceToken, ShouldEqual, serviceAuthToken)
				So(authorizerMock.AllowCalls()[0].UserToken, ShouldEqual, userAuthToken)
				So(authorizerMock.AllowCalls()[0].CollectionID, ShouldEqual, collectionID)
				So(authorizerMock.AllowCalls()[0].DatasetID, ShouldEqual, datasetID)
			})

			Convey("and a 500 response is returned", func() {
				So(w.Code, ShouldEqual, 500)
			})

			Convey("and the request does not continue", func() {
				So(handlerCalls, ShouldBeEmpty)
			})
		})
	})
}

func TestWriteErr(t *testing.T) {
	type TC struct {
		scenario     string
		given        string
		w            *ResponseWriterMoq
		status       int
		body         string
		assertStatus func(calls []int)
		assertBody   func(calls []string)
	}

	cases := []TC{
		{
			scenario: "The response body and status are written without error",
			given:    "Given a valid body and status",
			w: &ResponseWriterMoq{
				WriteHeaderCalls: []int{},
				WriteHeaderFunc:  func(statusCode int) {},
				WriteCalls:       []string{},
				WriteFunc: func(bytes []byte) (i int, e error) {
					return len(bytes), nil
				},
			},
			status: 401,
			assertStatus: func(calls []int) {
				So(calls, ShouldHaveLength, 1)
				So(calls[0], ShouldEqual, 401)
			},
			body: "unauthorized",
			assertBody: func(calls []string) {
				So(calls, ShouldHaveLength, 1)
				So(calls[0], ShouldEqual, "unauthorized")
			},
		},
		{
			scenario: "An error occurs while writing the response body so a 500 status is returned",
			given:    "Given write returns an error",
			w: &ResponseWriterMoq{
				WriteHeaderCalls: []int{},
				WriteHeaderFunc:  func(statusCode int) {},
				WriteCalls:       []string{},
				WriteFunc: func(bytes []byte) (i int, e error) {
					return 0, errors.New("By the power of Grey Skull!")
				},
			},
			status: 401,
			assertStatus: func(calls []int) {
				So(calls, ShouldHaveLength, 2)
				So(calls[0], ShouldEqual, 401)
				So(calls[1], ShouldEqual, 500)
			},
			body: "some error",
			assertBody: func(calls []string) {
				So(calls, ShouldHaveLength, 1)
				So(calls[0], ShouldEqual, "some error")
			},
		},
	}

	for i, tc := range cases {
		Convey(fmt.Sprintf("%d) %s", i, tc.given), t, func() {

			Convey("When writeErr is called", func() {
				writeErr(nil, tc.w, tc.status, tc.body, log.Data{})

				Convey("Then the expected body is written", func() {
					tc.assertBody(tc.w.WriteCalls)

					Convey("And the expected status is written", func() {
						tc.assertStatus(tc.w.WriteHeaderCalls)
					})
				})
			})
		})
	}
}

func TestHandleAuthorizeError(t *testing.T) {
	type tc struct {
		desc         string
		given        string
		inputErr     error
		w            *ResponseWriterMoq
		assertStatus func(calls []int)
		assertBody   func(calls []string)
	}

	testCases := []tc{
		{
			desc:  "write a permission.Error to the response",
			given: "given a permissions.Error",
			inputErr: permissions.Error{
				Status:  400,
				Message: "bad request",
			},
			w: &ResponseWriterMoq{
				WriteHeaderCalls: []int{},
				WriteHeaderFunc:  func(statusCode int) {},
				WriteCalls:       []string{},
				WriteFunc: func(bytes []byte) (i int, e error) {
					return len(bytes), nil
				},
			},
			assertStatus: func(calls []int) {
				So(calls, ShouldHaveLength, 1)
				So(calls[0], ShouldEqual, 400)
			},
			assertBody: func(calls []string) {
				So(calls, ShouldHaveLength, 1)
				So(calls[0], ShouldEqual, "bad request")
			},
		},
		{
			desc:  "write a standard error to the response",
			given: "given a error",
			inputErr: errors.New("bork bork bork"),
			w: &ResponseWriterMoq{
				WriteHeaderCalls: []int{},
				WriteHeaderFunc:  func(statusCode int) {},
				WriteCalls:       []string{},
				WriteFunc: func(bytes []byte) (i int, e error) {
					return len(bytes), nil
				},
			},
			assertStatus: func(calls []int) {
				So(calls, ShouldHaveLength, 1)
				So(calls[0], ShouldEqual, 500)
			},
			assertBody: func(calls []string) {
				So(calls, ShouldHaveLength, 1)
				So(calls[0], ShouldEqual, "internal server error")
			},
		},
	}

	for i, tc := range testCases {
		Convey(fmt.Sprintf("%d) %s", i, tc.given), t, func() {

			Convey("When handleAuthorizeError is called", func() {
				handleAuthorizeError(nil, tc.inputErr, tc.w, log.Data{})

				Convey("Then the expected status is set", func() {
					tc.assertStatus(tc.w.WriteHeaderCalls)

					Convey("And the expected body is set", func() {
						tc.assertBody(tc.w.WriteCalls)
					})
				})
			})

		})
	}
}

func getHandlerMoq(calls *[]handlerCalls) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		*calls = append(*calls, handlerCalls{R: r, W: w})
	}
}

func getRequestVarsMoq() func(r *http.Request) map[string]string {
	return func(r *http.Request) map[string]string {
		return map[string]string{"dataset_id": datasetID}
	}
}

func getRequest(t *testing.T) *http.Request {
	req, err := http.NewRequest("GET", "/something", nil)
	if err != nil {
		t.Fatalf("error creating http.Request: %s", err.Error())
	}
	req.Header.Set(common.AuthHeaderKey, serviceAuthToken)
	req.Header.Set(common.FlorenceHeaderKey, userAuthToken)
	req.Header.Set(CollectionIDHeader, collectionID)
	return req
}

func getAuthorizerMock(err error) *AuthorizerMock {
	return &AuthorizerMock{
		AllowFunc: func(ctx context.Context, required permissions.Policy, serviceToken string, userToken string, collectionID string, datasetID string) error {
			return err
		},
	}
}
