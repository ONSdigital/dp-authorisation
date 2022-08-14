package identityclient_test

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"

	"github.com/ONSdigital/dp-authorisation/v2/identityclient"

	"github.com/ONSdigital/dp-authorisation/v2/identityclient/mock"

	health "github.com/ONSdigital/dp-healthcheck/healthcheck"

	. "github.com/smartystreets/goconvey/convey"
)

const (
	testURL                = "www.dummytest.io"
	errorString            = "this is an error"
	testStatusOK           = 200
	clientTypeReflection   = "*http.Client"
	identityTypeReflection = "*identityclient.IdentityClient"
	healthCheckTestName    = "dp-authorisation-v2-test"
	jwtKeyRequestError     = "jwt keys request error"
	jwtKeyRequestOK        = "jwt keys request ok"
	healthErrorStatus      = "CRITICAL"
	healthOKStatus         = "OK"
	testJWTPublicKeyAPIMap = `{"test123=": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmwIDAQAB","test456=": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmwIDAQAB"}`
)

var (
	testError = errors.New("dummy test error")
)

func TestIndentityClient(t *testing.T) {
	ctx := context.Background()

	Convey("Ensure identityclient constructor returns correct types", t, func() {
		identityObject, _ := identityclient.NewIdentityClient(testURL, 1)
		So(reflect.TypeOf(identityObject).String(), ShouldResemble, identityTypeReflection)
		So(reflect.TypeOf(identityObject.Client).String(), ShouldResemble, clientTypeReflection)
	})

	Convey("Given a identity client instance created", t, func() {
		c := identityclient.IdentityClient{}
		identityClientTests := []struct {
			clientMock *mock.IdentityInterfaceMock
			response   map[string]interface{}
		}{
			{
				&mock.IdentityInterfaceMock{
					GetFunc: func(ctx context.Context, url string) (*http.Response, error) {
						r := &http.Response{
							StatusCode: http.StatusOK,
						}
						return r, nil
					},
				},
				map[string]interface{}{
					"statusCode": testStatusOK,
				},
			},
			{
				&mock.IdentityInterfaceMock{
					GetFunc: func(ctx context.Context, url string) (*http.Response, error) {
						return nil, errors.New(errorString)
					},
				},
				map[string]interface{}{
					"statusCode": nil,
				},
			},
		}

		for _, tt := range identityClientTests {
			c.Client = tt.clientMock
			r, _ := c.Get(ctx)
			if r != nil {
				So(r.StatusCode, ShouldEqual, tt.response["statusCode"])
			}
		}
	})
}

func TestIndentityClient_GetJWTVerificationKeys(t *testing.T) {
	Convey("Get JWT Verification keys - success", t, func() {
		ctx := context.Background()

		identityClient := identityclient.IdentityClient{
			Client: &mock.IdentityInterfaceMock{
				GetFunc: func(ctx context.Context, url string) (*http.Response, error) {
					r := &http.Response{
						StatusCode: http.StatusOK,
						Body:       ioutil.NopCloser(bytes.NewBufferString(testJWTPublicKeyAPIMap)),
					}
					return r, nil
				},
			},
		}
		err := identityClient.GetJWTVerificationKeys(ctx)

		So(err, ShouldBeNil)
		So(len(identityClient.JWTKeys), ShouldEqual, 2)
		So(identityClient.JWTKeys["test123="], ShouldEqual, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmwIDAQAB")
		So(identityClient.JWTKeys["test456="], ShouldEqual, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmwIDAQAB")
	})

	Convey("Get JWT Verification keys - dp-net Get request returns error", t, func() {
		ctx := context.Background()

		identityClient := identityclient.IdentityClient{
			Client: &mock.IdentityInterfaceMock{
				GetFunc: func(ctx context.Context, url string) (*http.Response, error) {
					return nil, testError
				},
			},
		}
		_ = identityClient.GetJWTVerificationKeys(ctx)

		So(identityClient.JWTKeys, ShouldBeNil)
	})
}

func TestIndentityClient_IdentityHealthCheck(t *testing.T) {
	ctx := context.Background()

	checkState := health.NewCheckState(healthCheckTestName)

	Convey("Get JWT Verification keys on health check call - success", t, func() {
		identityClient := identityclient.IdentityClient{
			BasicClient: &mock.IdentityInterfaceMock{
				GetFunc: func(ctx context.Context, url string) (*http.Response, error) {
					r := &http.Response{
						StatusCode: http.StatusOK,
						Body:       ioutil.NopCloser(bytes.NewBufferString(testJWTPublicKeyAPIMap)),
					}
					return r, nil
				},
			},
		}
		err := identityClient.IdentityHealthCheck(ctx, checkState)

		So(err, ShouldBeNil)
		So(len(identityClient.JWTKeys), ShouldEqual, 2)
		So(identityClient.JWTKeys["test123="], ShouldEqual, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmwIDAQAB")
		So(identityClient.JWTKeys["test456="], ShouldEqual, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmwIDAQAB")
		So(checkState.StatusCode(), ShouldEqual, http.StatusOK)
		So(checkState.Status(), ShouldEqual, healthOKStatus)
		So(checkState.Message(), ShouldEqual, jwtKeyRequestOK)
	})

	Convey("Get JWT Verification keys on health check call - success", t, func() {
		identityClient := identityclient.IdentityClient{
			BasicClient: &mock.IdentityInterfaceMock{
				GetFunc: func(ctx context.Context, url string) (*http.Response, error) {
					return nil, testError
				},
			},
		}
		err := identityClient.IdentityHealthCheck(ctx, checkState)

		So(err, ShouldNotBeNil)
		So(len(identityClient.JWTKeys), ShouldEqual, 0)
		So(checkState.StatusCode(), ShouldEqual, http.StatusInternalServerError)
		So(checkState.Status(), ShouldEqual, healthErrorStatus)
		So(checkState.Message(), ShouldEqual, jwtKeyRequestError)
	})
}
