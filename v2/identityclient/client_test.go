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
	testURL                   = "www.dummytest.io"
	errorString               = "this is an error"
	testStatusOK              = 200
	clientTypeReflection      = "*http.Client"
	identityTypeReflection    = "*identityclient.IdentityClient"
	testJWTPublicKeyAPIString = `{"GHB723n83jw=":"MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0TpTemKodQNChMNj1f/NF19nM","HUHJ83nbs8h=":"MIICIjANBAbjKbwRENSKujO5iwXLIt0hCjh5dz4egKQo7KEr2ex3qdy50LWKD871gRfAgDoRD5/1kUUVqII5K09IDCVY/EohukrI+Uep/Z5ymPNPXXD1yJvBx/YmmuMGUAT5UKHKBCP+FcoAxYAKcaKhtL0iyVjhtD0Y4V8gcQnQq3bOYhF4FEHoHBNh23AKcJM1VvNVtSHViMuTOzsFLHAgy2lLsRLnxtXovEovAiTay+Sn1FuDOq2gswl2Uujh1GO8kfkXE1gNRn/l7RUYIRrql8kROHMSYvPBAIqYhGSWOG3JX1oFlI1erYaeIPI4l4Qj/P+YSnrRx0di3vy6ZDAnhs8kdZP81F+3rFrNUNIOVFBRKscMnvOH4HO4f9PpXynde5xTlVvqdgXVlWkxGgQk0d323ka8fPY1xsmxV99idmmgmfglPOeLxuOkFxfXJSpbP/kn9AEyKBcF2BImfc12uvdSn46zZ1f/8nvzQ9naruwEtho4t6cIb7A+5KxVAILCQHvm3xIxfxMy5RFI=="}`
	healthCheckTestName       = "dp-authorisation-v2-test"
	jwtKeyRequestError        = "jwt keys request error"
	jwtKeyRequestOK           = "jwt keys request ok"
	healthErrorStatus         = "CRITICAL"
	healthOKStatus            = "OK"
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
						Body:       ioutil.NopCloser(bytes.NewBufferString(testJWTPublicKeyAPIString)),
					}
					return r, nil
				},
			},
		}
		err := identityClient.GetJWTVerificationKeys(ctx)

		So(err, ShouldBeNil)
		So(len(identityClient.JWTKeys), ShouldEqual, 2)
		So(identityClient.JWTKeys["GHB723n83jw="], ShouldEqual, "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0TpTemKodQNChMNj1f/NF19nM")
		So(identityClient.JWTKeys["HUHJ83nbs8h="], ShouldEqual, "MIICIjANBAbjKbwRENSKujO5iwXLIt0hCjh5dz4egKQo7KEr2ex3qdy50LWKD871gRfAgDoRD5/1kUUVqII5K09IDCVY/EohukrI+Uep/Z5ymPNPXXD1yJvBx/YmmuMGUAT5UKHKBCP+FcoAxYAKcaKhtL0iyVjhtD0Y4V8gcQnQq3bOYhF4FEHoHBNh23AKcJM1VvNVtSHViMuTOzsFLHAgy2lLsRLnxtXovEovAiTay+Sn1FuDOq2gswl2Uujh1GO8kfkXE1gNRn/l7RUYIRrql8kROHMSYvPBAIqYhGSWOG3JX1oFlI1erYaeIPI4l4Qj/P+YSnrRx0di3vy6ZDAnhs8kdZP81F+3rFrNUNIOVFBRKscMnvOH4HO4f9PpXynde5xTlVvqdgXVlWkxGgQk0d323ka8fPY1xsmxV99idmmgmfglPOeLxuOkFxfXJSpbP/kn9AEyKBcF2BImfc12uvdSn46zZ1f/8nvzQ9naruwEtho4t6cIb7A+5KxVAILCQHvm3xIxfxMy5RFI==")
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
						Body:       ioutil.NopCloser(bytes.NewBufferString(testJWTPublicKeyAPIString)),
					}
					return r, nil
				},
			},
		}
		err := identityClient.IdentityHealthCheck(ctx, checkState)

		So(err, ShouldBeNil)
		So(len(identityClient.JWTKeys), ShouldEqual, 2)
		So(identityClient.JWTKeys["GHB723n83jw="], ShouldEqual, "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0TpTemKodQNChMNj1f/NF19nM")
		So(identityClient.JWTKeys["HUHJ83nbs8h="], ShouldEqual, "MIICIjANBAbjKbwRENSKujO5iwXLIt0hCjh5dz4egKQo7KEr2ex3qdy50LWKD871gRfAgDoRD5/1kUUVqII5K09IDCVY/EohukrI+Uep/Z5ymPNPXXD1yJvBx/YmmuMGUAT5UKHKBCP+FcoAxYAKcaKhtL0iyVjhtD0Y4V8gcQnQq3bOYhF4FEHoHBNh23AKcJM1VvNVtSHViMuTOzsFLHAgy2lLsRLnxtXovEovAiTay+Sn1FuDOq2gswl2Uujh1GO8kfkXE1gNRn/l7RUYIRrql8kROHMSYvPBAIqYhGSWOG3JX1oFlI1erYaeIPI4l4Qj/P+YSnrRx0di3vy6ZDAnhs8kdZP81F+3rFrNUNIOVFBRKscMnvOH4HO4f9PpXynde5xTlVvqdgXVlWkxGgQk0d323ka8fPY1xsmxV99idmmgmfglPOeLxuOkFxfXJSpbP/kn9AEyKBcF2BImfc12uvdSn46zZ1f/8nvzQ9naruwEtho4t6cIb7A+5KxVAILCQHvm3xIxfxMy5RFI==")
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
