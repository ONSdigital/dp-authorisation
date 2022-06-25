package authorisation_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ONSdigital/dp-authorisation/v2/authorisationtest"
	dprequest "github.com/ONSdigital/dp-net/v2/request"

	"github.com/ONSdigital/dp-authorisation/v2/jwt"

	"github.com/ONSdigital/dp-authorisation/v2/authorisation"
	"github.com/ONSdigital/dp-authorisation/v2/authorisation/mock"
	"github.com/ONSdigital/dp-authorisation/v2/identityclient"
	identityClientMock "github.com/ONSdigital/dp-authorisation/v2/identityclient/mock"
	"github.com/ONSdigital/dp-authorisation/v2/permissions"

	. "github.com/smartystreets/goconvey/convey"
)

var (
	dummyEntityData             = &permissions.EntityData{UserID: "fred"}
	dummyAttributesData         = &map[string]string{"collection_id": "some-collection_id-uuid"}
	permission                  = "dataset.read"
	dummyServiveTokenEntityData = &permissions.EntityData{UserID: "bilbo.baggins@bilbo-baggins.io"}
	zebedeeIdentity             = &mock.ZebedeeClientMock{
		CheckTokenIdentityFunc: func(ctx context.Context, token string) (*dprequest.IdentityResponse, error) {
			return &dprequest.IdentityResponse{
				Identifier: "bilbo.baggins@bilbo-baggins.io",
			}, nil
		},
	}
	trimmedToken             = strings.TrimPrefix(authorisationtest.AdminJWTToken, "Bearer ")
	testURL                  = "https://the-url.com"
	testJWTPublicKeyAPIMapx1 = map[string]string{
		"test789=": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmwIDAQAB",
	}
	testJWTPublicKeyAPIMapx2 = map[string]string{
		"test123=": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmwIDAQAB",
		"test456=": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmwIDAQAB",
	}
)

type mockHandler struct {
	calls int
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.calls++
}

type mockAttributes struct {
	attributes map[string]string
	calls      int
}

func (m *mockAttributes) GetAttributes(req *http.Request) (attributes map[string]string, err error) {
	m.calls++
	return m.attributes, nil
}

var identityClient = &identityclient.IdentityClient{
	Client: &identityClientMock.IdentityInterfaceMock{
		GetFunc: func(ctx context.Context, url string) (*http.Response, error) {
			r := &http.Response{
				StatusCode: http.StatusOK,
			}
			return r, nil
		},
	},
}

var NewCognitoRSAParserTest, _ = jwt.NewCognitoRSAParser(testJWTPublicKeyAPIMapx1)

func TestMiddleware_RequireWithAttributes(t *testing.T) {
	Convey("Given a request with a valid JWT token and collection_id header that have the required permissions", t, func() {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, testURL, nil)
		request.Header.Set("Authorization", authorisationtest.AdminJWTToken)
		mockHandler := &mockHandler{calls: 0}
		mockJWTParser := newMockJWTParser()
		identityClient.CognitoRSAParser = NewCognitoRSAParserTest
		mockAttributes := mockAttributes{attributes: *dummyAttributesData, calls: 0}
		permissionsChecker := &mock.PermissionsCheckerMock{
			HasPermissionFunc: func(ctx context.Context, entityData permissions.EntityData, permission string, attributes map[string]string) (bool, error) {
				return true, nil
			},
		}

		middleware := authorisation.NewMiddlewareFromDependencies(mockJWTParser, permissionsChecker, zebedeeIdentity, identityClient)
		middlewareFunc := middleware.RequireWithAttributes(permission, mockHandler.ServeHTTP, mockAttributes.GetAttributes)

		Convey("When the middleware function is called", func() {
			middlewareFunc(response, request)

			Convey("Then the JWT parser is called as expected", func() {
				So(mockJWTParser.ParseCalls(), ShouldHaveLength, 1)
				So(mockJWTParser.ParseCalls()[0].TokenString, ShouldEqual, trimmedToken)
			})

			Convey("Then the request attributes func is called as expected", func() {
				So(mockAttributes.calls, ShouldEqual, 1)
			})

			Convey("Then the permissions checker is called as expected", func() {
				So(permissionsChecker.HasPermissionCalls(), ShouldHaveLength, 1)
				So(permissionsChecker.HasPermissionCalls()[0].Permission, ShouldEqual, permission)
				So(permissionsChecker.HasPermissionCalls()[0].EntityData, ShouldResemble, *dummyEntityData)
				So(permissionsChecker.HasPermissionCalls()[0].Attributes, ShouldResemble, *dummyAttributesData)
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

func TestMiddleware_Require(t *testing.T) {
	Convey("Given a request with a valid JWT token that has the required permissions", t, func() {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, testURL, nil)
		request.Header.Set("Authorization", authorisationtest.AdminJWTToken)
		request.Header.Set("Collection-Id", "123abc")
		expectMap := map[string]string{"collection_id": "123abc"}
		mockHandler := &mockHandler{calls: 0}
		mockJWTParser := newMockJWTParser()

		permissionsChecker := &mock.PermissionsCheckerMock{
			HasPermissionFunc: func(ctx context.Context, entityData permissions.EntityData, permission string, attributes map[string]string) (bool, error) {
				return true, nil
			},
		}

		middleware := authorisation.NewMiddlewareFromDependencies(mockJWTParser, permissionsChecker, zebedeeIdentity, identityClient)
		middlewareFunc := middleware.Require(permission, mockHandler.ServeHTTP)

		Convey("When the middleware function is called", func() {
			middlewareFunc(response, request)

			Convey("Then the JWT parser is called as expected", func() {
				So(mockJWTParser.ParseCalls(), ShouldHaveLength, 1)
				So(mockJWTParser.ParseCalls()[0].TokenString, ShouldEqual, trimmedToken)
			})

			Convey("Then the permissions checker is called as expected", func() {
				So(permissionsChecker.HasPermissionCalls(), ShouldHaveLength, 1)
				So(permissionsChecker.HasPermissionCalls()[0].Permission, ShouldEqual, permission)
				So(permissionsChecker.HasPermissionCalls()[0].EntityData, ShouldResemble, *dummyEntityData)
				So(permissionsChecker.HasPermissionCalls()[0].Attributes, ShouldResemble, expectMap)
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
		request := httptest.NewRequest(http.MethodGet, testURL, nil)
		mockHandler := &mockHandler{calls: 0}
		mockJWTParser := &mock.JWTParserMock{}
		permissionsChecker := &mock.PermissionsCheckerMock{}
		middleware := authorisation.NewMiddlewareFromDependencies(mockJWTParser, permissionsChecker, zebedeeIdentity, identityClient)
		middlewareFunc := middleware.Require(permission, mockHandler.ServeHTTP)

		Convey("When the middleware function is called", func() {
			middlewareFunc(response, request)

			Convey("Then the underlying HTTP handler is not called", func() {
				So(mockHandler.calls, ShouldEqual, 0)
			})

			Convey("Then the response code should be 401 unauthorised", func() {
				So(response.Code, ShouldEqual, http.StatusUnauthorized)
			})
		})
	})
}

func TestMiddleware_Require_JWTParseError(t *testing.T) {
	Convey("Given the JWT parse fails with an error", t, func() {
		expectedError := errors.New("failed to parse JWT token")
		mockJWTParser := &mock.JWTParserMock{
			ParseFunc: func(tokenString string) (*permissions.EntityData, error) {
				return nil, expectedError
			},
		}

		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, testURL, nil)
		request.Header.Set("Authorization", authorisationtest.AdminJWTToken)
		mockHandler := &mockHandler{calls: 0}
		permissionsChecker := &mock.PermissionsCheckerMock{}
		middleware := authorisation.NewMiddlewareFromDependencies(mockJWTParser, permissionsChecker, zebedeeIdentity, identityClient)
		middlewareFunc := middleware.Require(permission, mockHandler.ServeHTTP)

		Convey("When the middleware function is called", func() {
			middlewareFunc(response, request)

			Convey("Then the JWT parser is called as expected", func() {
				So(mockJWTParser.ParseCalls(), ShouldHaveLength, 1)
				So(mockJWTParser.ParseCalls()[0].TokenString, ShouldEqual, trimmedToken)
			})

			Convey("Then the underlying HTTP handler is not called", func() {
				So(mockHandler.calls, ShouldEqual, 0)
			})

			Convey("Then the response code should be 401 unauthorised", func() {
				So(response.Code, ShouldEqual, http.StatusUnauthorized)
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
		request := httptest.NewRequest(http.MethodGet, testURL, nil)
		request.Header.Set("Authorization", authorisationtest.AdminJWTToken)
		mockHandler := &mockHandler{calls: 0}
		mockJWTParser := newMockJWTParser()
		middleware := authorisation.NewMiddlewareFromDependencies(mockJWTParser, permissionsChecker, zebedeeIdentity, identityClient)
		middlewareFunc := middleware.Require(permission, mockHandler.ServeHTTP)

		Convey("When the middleware function is called", func() {
			middlewareFunc(response, request)

			Convey("Then the JWT parser is called as expected", func() {
				So(mockJWTParser.ParseCalls(), ShouldHaveLength, 1)
				So(mockJWTParser.ParseCalls()[0].TokenString, ShouldEqual, trimmedToken)
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
		request := httptest.NewRequest(http.MethodGet, testURL, nil)
		request.Header.Set("Authorization", authorisationtest.AdminJWTToken)
		mockHandler := &mockHandler{calls: 0}
		mockJWTParser := newMockJWTParser()
		middleware := authorisation.NewMiddlewareFromDependencies(mockJWTParser, permissionsChecker, zebedeeIdentity, identityClient)
		middlewareFunc := middleware.Require(permission, mockHandler.ServeHTTP)

		Convey("When the middleware function is called", func() {
			middlewareFunc(response, request)

			Convey("Then the JWT parser is called as expected", func() {
				So(mockJWTParser.ParseCalls(), ShouldHaveLength, 1)
				So(mockJWTParser.ParseCalls()[0].TokenString, ShouldEqual, trimmedToken)
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
		request := httptest.NewRequest(http.MethodGet, testURL, nil)
		request.Header.Set("Authorization", authorisationtest.ZebedeeServiceToken)
		mockHandler := &mockHandler{calls: 0}
		mockJWTParser := newMockJWTParser()
		middleware := authorisation.NewMiddlewareFromDependencies(mockJWTParser, permissionsChecker, zebedeeIdentity, identityClient)
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
		request := httptest.NewRequest(http.MethodGet, testURL, nil)
		request.Header.Set("Authorization", authorisationtest.ZebedeeServiceToken)
		mockHandler := &mockHandler{calls: 0}
		mockJWTParser := newMockJWTParser()
		middleware := authorisation.NewMiddlewareFromDependencies(mockJWTParser, permissionsChecker, zebedeeIdentity, identityClient)
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
		request := httptest.NewRequest(http.MethodGet, testURL, nil)
		request.Header.Set("Authorization", authorisationtest.ZebedeeServiceToken)
		mockHandler := &mockHandler{calls: 0}
		mockJWTParser := newMockJWTParser()
		middleware := authorisation.NewMiddlewareFromDependencies(mockJWTParser, permissionsChecker, zebedeeIdentity, identityClient)
		middlewareFunc := middleware.Require(permission, mockHandler.ServeHTTP)

		Convey("When the middleware function is called", func() {
			middlewareFunc(response, request)

			Convey("Then the JWT parser is called as expected", func() {
				So(mockJWTParser.ParseCalls(), ShouldHaveLength, 0)
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
func TestGetCollectionIdAttribute(t *testing.T) {
	Convey("Given a request with a Collection-Id header", t, func() {
		request := httptest.NewRequest(http.MethodGet, testURL, nil)
		request.Header.Set("Collection-Id", (*dummyAttributesData)["collection_id"])

		Convey("When the function is called", func() {
			attributes, err := authorisation.GetCollectionIdAttribute(request)

			Convey("Then the expected attributes value is returned", func() {
				So(attributes, ShouldResemble, *dummyAttributesData)
			})

			Convey("Then there is no error returned", func() {
				So(err, ShouldEqual, nil)
			})
		})
	})
}

func TestGetCollectionIdAttribute_NoCollectionIdHeader(t *testing.T) {
	Convey("Given a request without a Collection-Id header", t, func() {
		request := httptest.NewRequest(http.MethodGet, testURL, nil)
		request.Header.Set("Some-Other-Header", "Some-Value")

		Convey("When the function is called", func() {
			attributes, err := authorisation.GetCollectionIdAttribute(request)

			Convey("Then an empty attributes value is returned", func() {
				So(attributes, ShouldResemble, map[string]string{})
			})

			Convey("Then there is no error returned", func() {
				So(err, ShouldEqual, nil)
			})
		})
	})
}

func TestMiddleware_NewMiddlewareFromConfig_JWTKeys(t *testing.T) {
	Convey("Test Setting RSA Keys manually", t, func() {
		identityClient.JWTKeys = testJWTPublicKeyAPIMapx1
		rsaParser, _ := authorisation.NewCognitoRSAParser(identityClient.JWTKeys)

		So(len(rsaParser.PublicKeys), ShouldEqual, 1)
		So(rsaParser.PublicKeys["test789="], ShouldNotBeNil)
	})

	Convey("Test Setting RSA Keys via identity client", t, func() {
		identityClient.JWTKeys = testJWTPublicKeyAPIMapx2
		rsaParser, _ := authorisation.NewCognitoRSAParser(identityClient.JWTKeys)

		So(len(rsaParser.PublicKeys), ShouldEqual, 2)
		So(rsaParser.PublicKeys["test123="], ShouldNotBeNil)
		So(rsaParser.PublicKeys["test456="], ShouldNotBeNil)
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
