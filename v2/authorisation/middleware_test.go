package authorisation_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ONSdigital/dp-authorisation/v2/authorisationtest"
	dprequest "github.com/ONSdigital/dp-net/request"

	"github.com/ONSdigital/dp-authorisation/v2/authorisation"
	"github.com/ONSdigital/dp-authorisation/v2/authorisation/mock"
	"github.com/ONSdigital/dp-authorisation/v2/permissions"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	dummyEntityData = &permissions.EntityData{UserID: "fred"}
	permission      = "dataset.read"
	dummyServiveTokenEntityData = &permissions.EntityData{UserID: "bilbo.baggins@bilbo-baggins.io"}
	zebedeeIdentity = &mock.ZebedeeClientMock{
		CheckTokenIdentityFunc: func(ctx context.Context, token string) (*dprequest.IdentityResponse, error) {
			return &dprequest.IdentityResponse{
				Identifier: "bilbo.baggins@bilbo-baggins.io",
			}, nil
		},
	}
	trimmedToken = strings.TrimPrefix(authorisationtest.AdminJWTToken, "Bearer ")
)

type mockHandler struct {
	calls int
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.calls++
}

func TestMiddleware_Require(t *testing.T) {
	Convey("Given a request with a valid JWT token that has the required permissions", t, func() {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://the-url.com", nil)
		request.Header.Set("Authorization", authorisationtest.AdminJWTToken)
		mockHandler := &mockHandler{calls: 0}
		jwtParser := newMockJWTParser()

		permissionsChecker := &mock.PermissionsCheckerMock{
			HasPermissionFunc: func(ctx context.Context, entityData permissions.EntityData, permission string, attributes map[string]string) (bool, error) {
				return true, nil
			},
		}

		middleware := authorisation.NewMiddlewareFromDependencies(jwtParser, permissionsChecker, zebedeeIdentity)
		middlewareFunc := middleware.Require(permission, mockHandler.ServeHTTP)

		Convey("When the middleware function is called", func() {
			middlewareFunc(response, request)

			Convey("Then the JWT parser is called as expected", func() {
				So(jwtParser.ParseCalls(), ShouldHaveLength, 1)
				So(jwtParser.ParseCalls()[0].TokenString, ShouldEqual, trimmedToken)
			})

			Convey("Then the permissions checker is called as expected", func() {
				So(permissionsChecker.HasPermissionCalls(), ShouldHaveLength, 1)
				So(permissionsChecker.HasPermissionCalls()[0].Permission, ShouldEqual, permission)
				So(permissionsChecker.HasPermissionCalls()[0].EntityData, ShouldResemble, *dummyEntityData)
			})

			Convey("Then the underlying HTTP handler is called as expected", func() {
				So(mockHandler.calls, ShouldEqual, 1)
			})

			Convey("Then the response code should be 200", func() {
				So(response.Code, ShouldEqual, http.StatusOK)
			})
		})
	})
}

func TestMiddleware_Require_NoAuthHeader(t *testing.T) {
	Convey("Given a request without an authorization header", t, func() {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://the-url.com", nil)
		mockHandler := &mockHandler{calls: 0}
		jwtParser := &mock.JWTParserMock{}
		permissionsChecker := &mock.PermissionsCheckerMock{}
		middleware := authorisation.NewMiddlewareFromDependencies(jwtParser, permissionsChecker, zebedeeIdentity)
		middlewareFunc := middleware.Require(permission, mockHandler.ServeHTTP)

		Convey("When the middleware function is called", func() {
			middlewareFunc(response, request)

			Convey("Then the underlying HTTP handler is not called", func() {
				So(mockHandler.calls, ShouldEqual, 0)
			})

			Convey("Then the response code should be 403 forbidden", func() {
				So(response.Code, ShouldEqual, http.StatusForbidden)
			})
		})
	})
}

func TestMiddleware_Require_JWTParseError(t *testing.T) {
	Convey("Given the JWT parse fails with an error", t, func() {
		expectedError := errors.New("failed to parse JWT token")
		jwtParser := &mock.JWTParserMock{
			ParseFunc: func(tokenString string) (*permissions.EntityData, error) {
				return nil, expectedError
			},
		}

		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://the-url.com", nil)
		request.Header.Set("Authorization", authorisationtest.AdminJWTToken)
		mockHandler := &mockHandler{calls: 0}
		permissionsChecker := &mock.PermissionsCheckerMock{}
		middleware := authorisation.NewMiddlewareFromDependencies(jwtParser, permissionsChecker, zebedeeIdentity)
		middlewareFunc := middleware.Require(permission, mockHandler.ServeHTTP)

		Convey("When the middleware function is called", func() {
			middlewareFunc(response, request)

			Convey("Then the JWT parser is called as expected", func() {
				So(jwtParser.ParseCalls(), ShouldHaveLength, 1)
				So(jwtParser.ParseCalls()[0].TokenString, ShouldEqual, trimmedToken)
			})

			Convey("Then the underlying HTTP handler is not called", func() {
				So(mockHandler.calls, ShouldEqual, 0)
			})

			Convey("Then the response code should be 403 forbidden", func() {
				So(response.Code, ShouldEqual, http.StatusForbidden)
			})
		})
	})
}

func TestMiddleware_Require_PermissionsCheckerError(t *testing.T) {
	Convey("Given the permission check returns an error", t, func() {
		expectedError := errors.New("error checking permissions - probably means the cache failed to refresh")
		permissionsChecker := &mock.PermissionsCheckerMock{
			HasPermissionFunc: func(ctx context.Context, entityData permissions.EntityData, permission string, attributes map[string]string) (bool, error) {
				return false, expectedError
			},
		}

		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://the-url.com", nil)
		request.Header.Set("Authorization", authorisationtest.AdminJWTToken)
		mockHandler := &mockHandler{calls: 0}
		jwtParser := newMockJWTParser()
		middleware := authorisation.NewMiddlewareFromDependencies(jwtParser, permissionsChecker, zebedeeIdentity)
		middlewareFunc := middleware.Require(permission, mockHandler.ServeHTTP)

		Convey("When the middleware function is called", func() {
			middlewareFunc(response, request)

			Convey("Then the JWT parser is called as expected", func() {
				So(jwtParser.ParseCalls(), ShouldHaveLength, 1)
				So(jwtParser.ParseCalls()[0].TokenString, ShouldEqual, trimmedToken)
			})

			Convey("Then the permissions checker is called as expected", func() {
				So(permissionsChecker.HasPermissionCalls(), ShouldHaveLength, 1)
				So(permissionsChecker.HasPermissionCalls()[0].Permission, ShouldEqual, permission)
				So(permissionsChecker.HasPermissionCalls()[0].EntityData, ShouldResemble, *dummyEntityData)
			})

			Convey("Then the underlying HTTP handler is not called", func() {
				So(mockHandler.calls, ShouldEqual, 0)
			})

			Convey("Then the response code should be 500 internal server error", func() {
				So(response.Code, ShouldEqual, http.StatusInternalServerError)
			})
		})
	})
}

func TestMiddleware_Require_PermissionDenied(t *testing.T) {
	Convey("Given the permission check returns false", t, func() {
		permissionsChecker := &mock.PermissionsCheckerMock{
			HasPermissionFunc: func(ctx context.Context, entityData permissions.EntityData, permission string, attributes map[string]string) (bool, error) {
				return false, nil
			},
		}

		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://the-url.com", nil)
		request.Header.Set("Authorization", authorisationtest.AdminJWTToken)
		mockHandler := &mockHandler{calls: 0}
		jwtParser := newMockJWTParser()
		middleware := authorisation.NewMiddlewareFromDependencies(jwtParser, permissionsChecker, zebedeeIdentity)
		middlewareFunc := middleware.Require(permission, mockHandler.ServeHTTP)

		Convey("When the middleware function is called", func() {
			middlewareFunc(response, request)

			Convey("Then the JWT parser is called as expected", func() {
				So(jwtParser.ParseCalls(), ShouldHaveLength, 1)
				So(jwtParser.ParseCalls()[0].TokenString, ShouldEqual, trimmedToken)
			})

			Convey("Then the permissions checker is called as expected", func() {
				So(permissionsChecker.HasPermissionCalls(), ShouldHaveLength, 1)
				So(permissionsChecker.HasPermissionCalls()[0].Permission, ShouldEqual, permission)
				So(permissionsChecker.HasPermissionCalls()[0].EntityData, ShouldResemble, *dummyEntityData)
			})

			Convey("Then the underlying HTTP handler is not called", func() {
				So(mockHandler.calls, ShouldEqual, 0)
			})

			Convey("Then the response code should be 403 forbidden", func() {
				So(response.Code, ShouldEqual, http.StatusForbidden)
			})
		})
	})	
}

func TestMiddleware_ServiceTokenUser_SuccessfullyAuthorised(t *testing.T) {
	Convey("Given the permission check returns true", t, func() {
		permissionsChecker := &mock.PermissionsCheckerMock{
			HasPermissionFunc: func(ctx context.Context, entityData permissions.EntityData, permission string, attributes map[string]string) (bool, error) {
				return true, nil
			},
		}

		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://the-url.com", nil)
		request.Header.Set("Authorization", authorisationtest.ZebedeeServiceToken)
		mockHandler := &mockHandler{calls: 0}
		jwtParser := newMockJWTParser()
		middleware := authorisation.NewMiddlewareFromDependencies(jwtParser, permissionsChecker, zebedeeIdentity)
		middlewareFunc := middleware.Require(permission, mockHandler.ServeHTTP)

		Convey("When the middleware function is called", func() {
			middlewareFunc(response, request)

			Convey("Then the permissions checker is called as expected", func() {
				So(permissionsChecker.HasPermissionCalls(), ShouldHaveLength, 1)
				So(permissionsChecker.HasPermissionCalls()[0].Permission, ShouldEqual, permission)
				So(permissionsChecker.HasPermissionCalls()[0].EntityData, ShouldResemble, *dummyServiveTokenEntityData)
			})

			Convey("Then the underlying HTTP handler is called as expected", func() {
				So(mockHandler.calls, ShouldEqual, 1)
			})

			Convey("Then the response code should be 200", func() {
				So(response.Code, ShouldEqual, http.StatusOK)
			})
		})
	})
}

func TestMiddleware_ServiceTokenUser_AuthorisationDenied(t *testing.T) {
	Convey("Given the permission check returns false", t, func() {
		permissionsChecker := &mock.PermissionsCheckerMock{
			HasPermissionFunc: func(ctx context.Context, entityData permissions.EntityData, permission string, attributes map[string]string) (bool, error) {
				return false, nil
			},
		}

		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://the-url.com", nil)
		request.Header.Set("Authorization", authorisationtest.ZebedeeServiceToken)
		mockHandler := &mockHandler{calls: 0}
		jwtParser := newMockJWTParser()
		middleware := authorisation.NewMiddlewareFromDependencies(jwtParser, permissionsChecker, zebedeeIdentity)
		middlewareFunc := middleware.Require(permission, mockHandler.ServeHTTP)

		Convey("When the middleware function is called", func() {
			middlewareFunc(response, request)

			Convey("Then the permissions checker is called as expected", func() {
				So(permissionsChecker.HasPermissionCalls(), ShouldHaveLength, 1)
				So(permissionsChecker.HasPermissionCalls()[0].Permission, ShouldEqual, permission)
				So(permissionsChecker.HasPermissionCalls()[0].EntityData, ShouldResemble, *dummyServiveTokenEntityData)
			})

			Convey("Then the underlying HTTP handler is not called", func() {
				So(mockHandler.calls, ShouldEqual, 0)
			})

			Convey("Then the response code should be 403 forbidden", func() {
				So(response.Code, ShouldEqual, http.StatusForbidden)
			})
		})
	})
}


func TestMiddleware_ServiceTokenUser_ZebedeeIdentityVerificationError(t *testing.T) {
	Convey("Given the permission check returns false", t, func() {
		permissionsChecker := &mock.PermissionsCheckerMock{
			HasPermissionFunc: func(ctx context.Context, entityData permissions.EntityData, permission string, attributes map[string]string) (bool, error) {
				return true, nil
			},
		}

		zebedeeIdentity = &mock.ZebedeeClientMock{
			CheckTokenIdentityFunc: func(ctx context.Context, token string) (*dprequest.IdentityResponse, error) {
				return nil, errors.New("service token not valid")
			},
		}

		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://the-url.com", nil)
		request.Header.Set("Authorization", authorisationtest.ZebedeeServiceToken)
		mockHandler := &mockHandler{calls: 0}
		jwtParser := newMockJWTParser()
		middleware := authorisation.NewMiddlewareFromDependencies(jwtParser, permissionsChecker, zebedeeIdentity)
		middlewareFunc := middleware.Require(permission, mockHandler.ServeHTTP)

		Convey("When the middleware function is called", func() {
			middlewareFunc(response, request)

			Convey("Then the JWT parser is called as expected", func() {
				So(jwtParser.ParseCalls(), ShouldHaveLength, 0)
			})

			Convey("Then the underlying HTTP handler is not called", func() {
				So(mockHandler.calls, ShouldEqual, 0)
			})

			Convey("Then the response code should be 403 forbidden", func() {
				So(response.Code, ShouldEqual, http.StatusForbidden)
			})
		})
	})
}

func newMockJWTParser() *mock.JWTParserMock {
	jwtParser := &mock.JWTParserMock{
		ParseFunc: func(tokenString string) (*permissions.EntityData, error) {
			return dummyEntityData, nil
		},
	}
	return jwtParser
}
