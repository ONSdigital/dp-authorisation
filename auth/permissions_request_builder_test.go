package auth

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/ONSdigital/go-ns/common"
	. "github.com/smartystreets/goconvey/convey"
)

func TestPermissionsRequestBuilder_NewPermissionsRequest(t *testing.T) {
	Convey("should return expected error if host is empty", t, func() {
		builder := &PermissionsRequestBuilder{}

		actual, err := builder.NewPermissionsRequest(nil)

		permErr, ok := err.(Error)
		So(ok, ShouldBeTrue)
		So(permErr.Status, ShouldEqual, 500)
		So(permErr.Message, ShouldEqual, "PermissionsRequestBuilder configuration invalid host required but was empty")
		So(actual, ShouldBeNil)
	})

	Convey("should return expected error if inbound request is nil", t, func() {
		builder := &PermissionsRequestBuilder{Host: host}

		actual, err := builder.NewPermissionsRequest(nil)

		permErr, ok := err.(Error)
		So(ok, ShouldBeTrue)
		So(permErr, ShouldResemble, requestRequiredButNilError)
		So(actual, ShouldBeNil)
	})

	Convey("should return expected error if inbound request does not contain a user or service auth header", t, func() {
		builder := &PermissionsRequestBuilder{Host: host}
		inboundReq := httptest.NewRequest("GET", host, nil)

		actual, err := builder.NewPermissionsRequest(inboundReq)

		permErr, ok := err.(Error)
		So(ok, ShouldBeTrue)
		So(permErr, ShouldResemble, noUserOrServiceAuthTokenProvidedError)
		So(actual, ShouldBeNil)
	})

	Convey("should return expected error if error creating new http request", t, func() {
		builder := &PermissionsRequestBuilder{Host: "$%^&*(()"}
		inboundReq := httptest.NewRequest("GET", host, nil)
		inboundReq.Header.Set(common.FlorenceHeaderKey, "666")

		actual, err := builder.NewPermissionsRequest(inboundReq)

		permErr, ok := err.(Error)
		So(ok, ShouldBeTrue)
		So(permErr.Status, ShouldEqual, 500)
		So(permErr.Message, ShouldEqual, "error creating get dataset permissions http request")
		So(actual, ShouldBeNil)
	})

	Convey("should return get user permissions request if inbound request contains user auth header", t, func() {
		builder := &PermissionsRequestBuilder{Host: host}
		inboundReq := httptest.NewRequest("GET", host, nil)
		inboundReq.Header.Set(common.FlorenceHeaderKey, "666")

		actual, err := builder.NewPermissionsRequest(inboundReq)

		So(err, ShouldBeNil)
		So(actual.URL.String(), ShouldEqual, fmt.Sprintf(userInstancePermissionsURL, host))
		So(actual.Header.Get(common.FlorenceHeaderKey), ShouldEqual, "666")
	})

	Convey("should return get service permissions request if inbound request contains service auth header", t, func() {
		builder := &PermissionsRequestBuilder{Host: host}
		inboundReq := httptest.NewRequest("GET", host, nil)
		inboundReq.Header.Set(common.AuthHeaderKey, "666")

		actual, err := builder.NewPermissionsRequest(inboundReq)

		So(err, ShouldBeNil)
		So(actual.URL.String(), ShouldEqual, fmt.Sprintf(serviceInstancePermissionsURL, host))
		So(actual.Header.Get(common.AuthHeaderKey), ShouldEqual, "666")
	})

	Convey("should return get user permissions request if inbound request contains both user and service auth headers", t, func() {
		builder := &PermissionsRequestBuilder{Host: host}
		inboundReq := httptest.NewRequest("GET", host, nil)
		inboundReq.Header.Set(common.AuthHeaderKey, "666")
		inboundReq.Header.Set(common.FlorenceHeaderKey, "777")

		actual, err := builder.NewPermissionsRequest(inboundReq)

		So(err, ShouldBeNil)
		So(actual.URL.String(), ShouldEqual, fmt.Sprintf(userInstancePermissionsURL, host))
		So(actual.Header.Get(common.FlorenceHeaderKey), ShouldEqual, "777")
		So(actual.Header.Get(common.AuthHeaderKey), ShouldBeEmpty)
	})
}
