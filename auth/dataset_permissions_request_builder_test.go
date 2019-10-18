package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ONSdigital/dp-api-clients-go/headers"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	testHost     = "http://localhost:8080"
	datasetIDKey = "dataset_id"
)

func TestDatasetPermissionsRequestBuilder_NewPermissionsRequest(t *testing.T) {

	Convey("should return expected error if host key is empty", t, func() {
		builder := &DatasetPermissionsRequestBuilder{}
		req := httptest.NewRequest("GET", testHost, nil)

		actual, err := builder.NewPermissionsRequest(req)

		permErr, ok := err.(Error)
		So(ok, ShouldBeTrue)
		So(permErr.Status, ShouldEqual, 500)
		So(permErr.Message, ShouldEqual, "DatasetPermissionsRequestBuilder configuration invalid host required but was empty")
		So(actual, ShouldBeNil)
	})

	Convey("should return expected error if datasetID key is empty", t, func() {
		builder := &DatasetPermissionsRequestBuilder{
			Host: testHost,
		}

		req := httptest.NewRequest("GET", testHost, nil)

		actual, err := builder.NewPermissionsRequest(req)

		permErr, ok := err.(Error)
		So(ok, ShouldBeTrue)
		So(permErr.Status, ShouldEqual, 500)
		So(permErr.Message, ShouldEqual, "DatasetPermissionsRequestBuilder configuration invalid datasetID key required but was empty")
		So(actual, ShouldBeNil)
	})

	Convey("should return expected error if GetRequestVarsFunc is nil", t, func() {
		builder := &DatasetPermissionsRequestBuilder{
			Host:         testHost,
			DatasetIDKey: "dataset_id",
		}
		req := httptest.NewRequest("GET", testHost, nil)

		actual, err := builder.NewPermissionsRequest(req)

		permErr, ok := err.(Error)
		So(ok, ShouldBeTrue)
		So(permErr.Status, ShouldEqual, 500)
		So(permErr.Message, ShouldEqual, "DatasetPermissionsRequestBuilder configuration invalid GetRequestVarsFunc required but was nil")
		So(actual, ShouldBeNil)
	})

	Convey("should return expected error if request is nil", t, func() {
		builder := &DatasetPermissionsRequestBuilder{
			Host:               testHost,
			DatasetIDKey:       "dataset_id",
			GetRequestVarsFunc: getRequestVarsFunc(nil),
		}

		actual, err := builder.NewPermissionsRequest(nil)

		permErr, ok := err.(Error)

		So(ok, ShouldBeTrue)
		So(permErr, ShouldResemble, requestRequiredButNilError)
		So(actual, ShouldBeNil)
	})

	Convey("should return expected error if the request contains no user or service auth header", t, func() {
		builder := &DatasetPermissionsRequestBuilder{
			Host:               testHost,
			DatasetIDKey:       "dataset_id",
			GetRequestVarsFunc: getRequestVarsFunc(nil),
		}

		req := httptest.NewRequest("GET", testHost, nil)

		actual, err := builder.NewPermissionsRequest(req)

		permErr, ok := err.(Error)
		So(ok, ShouldBeTrue)
		So(permErr, ShouldResemble, noUserOrServiceAuthTokenProvidedError)
		So(actual, ShouldBeNil)

	})

	Convey("should return expected get user dataset permissions request", t, func() {
		builder := &DatasetPermissionsRequestBuilder{
			Host:         testHost,
			DatasetIDKey: "dataset_id",
			GetRequestVarsFunc: getRequestVarsFunc(map[string]string{
				datasetIDKey: "333",
			}),
		}

		req := httptest.NewRequest("GET", testHost, nil)
		headers.SetUserAuthToken(req, "111")
		headers.SetCollectionID(req, "222")

		actual, err := builder.NewPermissionsRequest(req)

		So(err, ShouldBeNil)
		So(actual.URL.String(), ShouldEqual, fmt.Sprintf(userDatasetPermissionsURL, testHost, "333", "222"))

		token, err := headers.GetUserAuthToken(actual)
		So(err, ShouldBeNil)
		So(token, ShouldEqual, "111")
	})

	Convey("should return expected get service dataset permissions request", t, func() {
		builder := &DatasetPermissionsRequestBuilder{
			Host:         testHost,
			DatasetIDKey: "dataset_id",
			GetRequestVarsFunc: getRequestVarsFunc(map[string]string{
				datasetIDKey: "333",
			}),
		}

		req := httptest.NewRequest("GET", testHost, nil)
		headers.SetServiceAuthToken(req, "111")

		actual, err := builder.NewPermissionsRequest(req)

		So(err, ShouldBeNil)
		So(actual.URL.String(), ShouldEqual, fmt.Sprintf(serviceDatasetPermissionsURL, testHost, "333"))

		token, err := headers.GetServiceAuthToken(actual)
		So(err, ShouldBeNil)
		So(token, ShouldEqual, "111")
	})

	Convey("should return get user dataset permissions request if request contains both user and service auth headers", t, func() {
		builder := &DatasetPermissionsRequestBuilder{
			Host:         testHost,
			DatasetIDKey: "dataset_id",
			GetRequestVarsFunc: getRequestVarsFunc(map[string]string{
				datasetIDKey: "111",
			}),
		}

		req := httptest.NewRequest("GET", testHost, nil)

		headers.SetServiceAuthToken(req, "222")
		headers.SetUserAuthToken(req, "333")
		headers.SetCollectionID(req, "444")

		actual, err := builder.NewPermissionsRequest(req)

		So(err, ShouldBeNil)
		So(actual.URL.String(), ShouldEqual, fmt.Sprintf(userDatasetPermissionsURL, testHost, "111", "444"))

		token, err := headers.GetUserAuthToken(actual)
		So(err, ShouldBeNil)
		So(token, ShouldEqual, "333")
	})
}

func TestCreateRequest(t *testing.T) {
	Convey("should return expected error if new http request fails", t, func() {
		actual, err := createRequest("£$%^&*()")

		permErr, ok := err.(Error)
		So(ok, ShouldBeTrue)
		So(permErr.Status, ShouldEqual, 500)
		So(permErr.Message, ShouldEqual, "error creating get dataset permissions http request")
		So(actual, ShouldBeNil)
	})
}

func getRequestVarsFunc(m map[string]string) func(r *http.Request) map[string]string {
	return func(r *http.Request) map[string]string {
		return m
	}
}
