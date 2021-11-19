package permissions_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ONSdigital/dp-authorisation/v2/permissions"
	dphttp "github.com/ONSdigital/dp-net/http"
	. "github.com/smartystreets/goconvey/convey"
)

var host = "localhost:1234"

var backoffSchedule = []time.Duration{
	1 * time.Second,
	3 * time.Second,
	6 * time.Second,
}

func TestAPIClient_GetPermissionsBundle(t *testing.T) {
	ctx := context.Background()

	Convey("Given a mock http client that returns a successful permissions bundle response", t, func() {
		httpClient := &dphttp.ClienterMock{
			DoFunc: func(ctx context.Context, req *http.Request) (*http.Response, error) {

				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader(getExampleBundleJson())),
				}, nil
			},
		}
		apiClient := permissions.NewAPIClient(host, httpClient, backoffSchedule)

		Convey("When GetPermissionsBundle is called", func() {

			bundle, err := apiClient.GetPermissionsBundle(ctx)

			Convey("Then no error is returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the expected permissions bundle is returned", func() {
				So(bundle, ShouldNotBeNil)

				policies := bundle["permission/admin"]["group/admin"]
				So(policies, ShouldHaveLength, 1)

				policy := policies[0]
				So(policy.ID, ShouldEqual, "policy/123")
				So(policy.Conditions[0].Attributes, ShouldHaveLength, 1)
				So(policy.Conditions[0].Attributes[0], ShouldEqual, "collection_id")
				So(policy.Conditions[0].Operator, ShouldEqual, "equals")
				So(policy.Conditions[0].Values, ShouldHaveLength, 1)
				So(policy.Conditions[0].Values[0], ShouldEqual, "col123")
			})
		})
	})
}

func TestAPIClient_GetPermissionsBundle_SucceedsOnSecondAttempt(t *testing.T) {
	ctx := context.Background()

	// GetPermissionsBundle request counter
	retryCount := 1

	Convey("Given a mock http client that returns a successful permissions bundle response", t, func() {
		httpClient := &dphttp.ClienterMock{
			DoFunc: func(ctx context.Context, req *http.Request) (*http.Response, error) {
				if retryCount == 1 {
					retryCount++
					return &http.Response{
						StatusCode: http.StatusInternalServerError,
						Body:       ioutil.NopCloser(strings.NewReader(`bad response`)),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(bytes.NewReader(getExampleBundleJson())),
				}, nil
			},
		}
		apiClient := permissions.NewAPIClient(host, httpClient, backoffSchedule)

		Convey("When GetPermissionsBundle is called", func() {

			bundle, err := apiClient.GetPermissionsBundle(ctx)

			Convey("Bundle request made twice (failed on first attempt)", func() {
				So(retryCount, ShouldEqual, 2)
			})

			Convey("Then no error is returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the expected permissions bundle is returned", func() {
				So(bundle, ShouldNotBeNil)

				policies := bundle["permission/admin"]["group/admin"]
				So(policies, ShouldHaveLength, 1)

				policy := policies[0]
				So(policy.ID, ShouldEqual, "policy/123")
				So(policy.Conditions[0].Attributes, ShouldHaveLength, 1)
				So(policy.Conditions[0].Attributes[0], ShouldEqual, "collection_id")
				So(policy.Conditions[0].Operator, ShouldEqual, "equals")
				So(policy.Conditions[0].Values, ShouldHaveLength, 1)
				So(policy.Conditions[0].Values[0], ShouldEqual, "col123")
			})
		})
	})
}

func TestAPIClient_GetPermissionsBundle_HTTPError(t *testing.T) {
	ctx := context.Background()
	expectedErr := errors.New("something went wrong")

	Convey("Given a mock http client that returns an error", t, func() {
		httpClient := &dphttp.ClienterMock{
			DoFunc: func(ctx context.Context, req *http.Request) (*http.Response, error) {
				return nil, expectedErr
			},
		}
		apiClient := permissions.NewAPIClient(host, httpClient, backoffSchedule)

		Convey("When GetPermissionsBundle is called", func() {

			bundle, err := apiClient.GetPermissionsBundle(ctx)

			Convey("Then the expected error is returned", func() {
				So(err, ShouldEqual, expectedErr)
			})

			Convey("Then the permissions bundle is nil", func() {
				So(bundle, ShouldBeNil)
			})
		})
	})
}

func TestAPIClient_GetPermissionsBundle_Non200ResponseCodeReturned(t *testing.T) {
	ctx := context.Background()

	Convey("Given a mock http client that returns a response code other than 200", t, func() {
		httpClient := &dphttp.ClienterMock{
			DoFunc: func(ctx context.Context, req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Status:     "500 internal server error",
				}, nil
			},
		}
		apiClient := permissions.NewAPIClient(host, httpClient, backoffSchedule)

		Convey("When GetPermissionsBundle is called", func() {

			bundle, err := apiClient.GetPermissionsBundle(ctx)

			Convey("Then the expected error is returned", func() {
				So(err.Error(), ShouldEqual, "bundler data not successfully retrieved from service - max retries reached [2] - final response: 500")
			})

			Convey("Then the permissions bundle is nil", func() {
				So(bundle, ShouldBeNil)
			})
		})
	})
}

func TestAPIClient_GetPermissionsBundle_NilResponseBody(t *testing.T) {
	ctx := context.Background()

	Convey("Given a mock http client that returns a response with a nil body", t, func() {
		httpClient := &dphttp.ClienterMock{
			DoFunc: func(ctx context.Context, req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
				}, nil
			},
		}
		apiClient := permissions.NewAPIClient(host, httpClient, backoffSchedule)

		Convey("When GetPermissionsBundle is called", func() {

			bundle, err := apiClient.GetPermissionsBundle(ctx)

			Convey("Then the expected error is returned", func() {
				So(err, ShouldEqual, permissions.ErrGetPermissionsResponseBodyNil)
			})

			Convey("Then the permissions bundle is nil", func() {
				So(bundle, ShouldBeNil)
			})
		})
	})
}

func TestAPIClient_GetPermissionsBundle_UnexpectedResponseBody(t *testing.T) {
	ctx := context.Background()

	Convey("Given a mock http client that returns a response with unexpected body content", t, func() {
		httpClient := &dphttp.ClienterMock{
			DoFunc: func(ctx context.Context, req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       ioutil.NopCloser(strings.NewReader(`bad response`)),
				}, nil
			},
		}
		apiClient := permissions.NewAPIClient(host, httpClient, backoffSchedule)

		Convey("When GetPermissionsBundle is called", func() {

			bundle, err := apiClient.GetPermissionsBundle(ctx)

			Convey("Then the expected error is returned", func() {
				So(err, ShouldEqual, permissions.ErrFailedToParsePermissionsResponse)
			})

			Convey("Then the permissions bundle is nil", func() {
				So(bundle, ShouldBeNil)
			})
		})
	})
}

func getExampleBundleJson() []byte {
	bundle := getExampleBundle()
	permissionsBundleJson, err := json.Marshal(bundle)
	So(err, ShouldBeNil)
	return permissionsBundleJson
}

func getExampleBundle() permissions.Bundle {

	bundle := permissions.Bundle{
		"permission/admin": map[string][]permissions.Policy{
			"group/admin": {
				{
					ID: "policy/123",
					Conditions: []permissions.Condition{
						{
							Attributes: []string{"collection_id"},
							Operator:   "equals",
							Values:     []string{"col123"}},
					},
				},
			},
		},
	}
	return bundle
}
