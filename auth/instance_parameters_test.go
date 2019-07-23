package auth

import (
	"net/http/httptest"
	"testing"

	"github.com/ONSdigital/go-ns/common"
	. "github.com/smartystreets/goconvey/convey"
)

var (
	host = "http://localhost:1234"
)

func TestInstanceParameterFactory_CreateParameters(t *testing.T) {
	Convey("should return expected error if request nil", t, func() {
		factory := &InstanceParameterFactory{}

		actual, err := factory.CreateParameters(nil)

		permErr, ok := err.(Error)
		So(ok, ShouldBeTrue)
		So(permErr, ShouldResemble, requestRequiredButNilError)
		So(actual, ShouldBeNil)
	})

	Convey("should return expected error if request does not contain a user or service auth header", t, func() {
		req := httptest.NewRequest("GET", host, nil)
		factory := &InstanceParameterFactory{}

		actual, err := factory.CreateParameters(req)

		permErr, ok := err.(Error)
		So(ok, ShouldBeTrue)
		So(permErr, ShouldResemble, noUserOrServiceAuthTokenProvidedError)
		So(actual, ShouldBeNil)
	})

	Convey("should return expected UserInstanceParameters if request contains a user auth token header", t, func() {
		req := httptest.NewRequest("GET", host, nil)
		req.Header.Set(common.FlorenceHeaderKey, "666")
		factory := &InstanceParameterFactory{}

		actual, err := factory.CreateParameters(req)

		So(err, ShouldBeNil)
		userInstanceParams, ok := actual.(*UserInstanceParameters)
		So(ok, ShouldBeTrue)
		So(userInstanceParams.UserAuthToken, ShouldEqual, "666")
	})

	Convey("should return expected ServiceInstanceParameters if request contains a service auth token header", t, func() {
		req := httptest.NewRequest("GET", host, nil)
		req.Header.Set(common.AuthHeaderKey, "666")
		factory := &InstanceParameterFactory{}

		actual, err := factory.CreateParameters(req)

		So(err, ShouldBeNil)
		serviceInstanceParams, ok := actual.(*ServiceInstanceParameters)
		So(ok, ShouldBeTrue)
		So(serviceInstanceParams.ServiceAuthToken, ShouldEqual, "666")
	})

	Convey("should return UserInstanceParameters if request contains both user and service auth token headers", t, func() {
		req := httptest.NewRequest("GET", host, nil)
		req.Header.Set(common.AuthHeaderKey, "666")
		req.Header.Set(common.FlorenceHeaderKey, "777")
		factory := &InstanceParameterFactory{}

		actual, err := factory.CreateParameters(req)

		So(err, ShouldBeNil)
		params, ok := actual.(*UserInstanceParameters)
		So(ok, ShouldBeTrue)
		So(params.UserAuthToken, ShouldEqual, "777")
	})
}

func TestUserInstanceParameters_CreateGetPermissionsRequest(t *testing.T) {
	Convey("should return expected error if host is empty", t, func() {
		p := &UserInstanceParameters{}

		actual, err := p.CreateGetPermissionsRequest("")

		So(err, ShouldResemble, hostRequiredButEmptyError)
		So(actual, ShouldBeNil)
	})

	Convey("should return error if host invalid", t, func() {
		p := &UserInstanceParameters{}
		actual, err := p.CreateGetPermissionsRequest("@£$%^&*()_")

		permErr, ok := err.(Error)

		So(ok, ShouldBeTrue)
		So(permErr.Status, ShouldEqual, 500)
		So(actual, ShouldBeNil)
	})

	Convey("should return expected request for valid host", t, func() {
		p := &UserInstanceParameters{
			UserAuthToken: "666",
		}

		actual, err := p.CreateGetPermissionsRequest(host)

		So(err, ShouldBeNil)
		So(actual.URL.Path, ShouldEqual, "/userInstancePermissions")
		So(actual.Header.Get(common.FlorenceHeaderKey), ShouldEqual, "666")
	})
}

func TestServiceInstanceParameters_CreateGetPermissionsRequest(t *testing.T) {
	Convey("should return expected error if host is empty", t, func() {
		p := &ServiceInstanceParameters{}

		actual, err := p.CreateGetPermissionsRequest("")

		So(err, ShouldResemble, requestRequiredButNilError)
		So(actual, ShouldBeNil)
	})

	Convey("should return expected error if host invalid", t, func() {
		p := &ServiceInstanceParameters{}

		actual, err := p.CreateGetPermissionsRequest("£$%^&*((((((")

		permErr, ok := err.(Error)
		So(ok, ShouldBeTrue)
		So(permErr.Status, ShouldEqual, 500)
		So(permErr.Message, ShouldEqual, "error creating new get user dataset permissions http request")
		So(actual, ShouldBeNil)
	})

	Convey("should return expected ServiceInstanceParameters", t, func() {
		p := &ServiceInstanceParameters{ServiceAuthToken: "666"}

		actual, err := p.CreateGetPermissionsRequest(host)

		So(err, ShouldBeNil)
		So(actual.URL.Path, ShouldEqual, "/serviceInstancePermissions")
		So(actual.Host, ShouldEqual, "localhost:1234")
		So(actual.Header.Get(common.AuthHeaderKey), ShouldEqual, "666")
	})
}
