package permissions

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/ONSdigital/dp-permissions/permissions/mocks"
	. "github.com/smartystreets/goconvey/convey"
)

// test fixture for permissions.Vet test
var vertPermissionsTestCases = []vetPermissionsTestCase{
	{
		desc:           "the caller has the required permissions",
		responseStatus: 200,
		body:           callerPermissions{List: []permission{Create, Read, Update, Delete}},
		bodyErr:        nil,
		require:        CRUD{Create: true, Read: true, Update: true, Delete: true},
		assertErrorExpected: func(err error) {
			So(err, ShouldBeNil)
		},
	},
	{
		desc:           "the caller does not have the required permissions",
		responseStatus: 200,
		body:           callerPermissions{List: []permission{Read}},
		bodyErr:        nil,
		require:        CRUD{Create: true, Read: true, Update: true, Delete: true},
		assertErrorExpected: func(err error) {
			permErr, ok := err.(Error)
			So(ok, ShouldBeTrue)
			So(permErr.Status, ShouldEqual, 403)
			So(permErr.Message, ShouldEqual, "caller does not have the required permission to perform the requested action")
			So(permErr.Cause, ShouldBeNil)
		},
	},
	{
		desc:           "the caller is unauthorized",
		responseStatus: 401,
		body:           errorEntity{Message: "unauthorized"},
		bodyErr:        nil,
		require:        CRUD{Create: true, Read: true, Update: true, Delete: true},
		assertErrorExpected: func(err error) {
			permErr, ok := err.(Error)
			So(ok, ShouldBeTrue)
			So(permErr.Status, ShouldEqual, 401)
			So(permErr.Message, ShouldEqual, "unauthorized")
			So(permErr.Cause, ShouldBeNil)
		},
	},
	{
		desc:           "the request is not valid",
		responseStatus: 400,
		body:           errorEntity{Message: "bad request"},
		bodyErr:        nil,
		require:        CRUD{Create: true, Read: true, Update: true, Delete: true},
		assertErrorExpected: func(err error) {
			permErr, ok := err.(Error)
			So(ok, ShouldBeTrue)
			So(permErr.Status, ShouldEqual, 400)
			So(permErr.Message, ShouldEqual, "bad request")
			So(permErr.Cause, ShouldBeNil)
		},
	},
	{
		desc:           "the requested collectionID & dataset combination does not exist",
		responseStatus: 404,
		body:           errorEntity{Message: "not found"},
		bodyErr:        nil,
		require:        CRUD{Create: true, Read: true, Update: true, Delete: true},
		assertErrorExpected: func(err error) {
			permErr, ok := err.(Error)
			So(ok, ShouldBeTrue)
			So(permErr.Status, ShouldEqual, 404)
			So(permErr.Message, ShouldEqual, "not found")
			So(permErr.Cause, ShouldBeNil)
		},
	},
	{
		desc:           "the get permissions request return an error",
		responseStatus: 500,
		body:           nil,
		responseErr:    errors.New("pop"),
		require:        CRUD{Create: true, Read: true, Update: true, Delete: true},
		assertErrorExpected: func(err error) {
			permErr, ok := err.(Error)
			So(ok, ShouldBeTrue)
			So(permErr.Status, ShouldEqual, 500)
			So(permErr.Message, ShouldEqual, "get permissions request returned an error")
			So(permErr.Cause, ShouldResemble, errors.New("pop"))
		},
	},
	{
		desc:           "the get permissions error response entity is invalid",
		responseStatus: 500,
		body:           666,
		bodyErr:        nil,
		require:        CRUD{Create: true, Read: true, Update: true, Delete: true},
		assertErrorExpected: func(err error) {
			permErr, ok := err.(Error)
			So(ok, ShouldBeTrue)
			So(permErr.Status, ShouldEqual, 500)
			So(permErr.Message, ShouldEqual, "internal server error failed unmarshalling get permissions error response body")
			_, isJsonErr := permErr.Cause.(*json.UnmarshalTypeError)
			So(isJsonErr, ShouldBeTrue)
		},
	},
	{
		desc:           "the get permissions success response entity is invalid",
		responseStatus: 200,
		body:           666,
		bodyErr:        nil,
		require:        CRUD{Create: true, Read: true, Update: true, Delete: true},
		assertErrorExpected: func(err error) {
			permErr, ok := err.(Error)
			So(ok, ShouldBeTrue)
			So(permErr.Status, ShouldEqual, 500)
			So(permErr.Message, ShouldEqual, "internal server error failed marshalling response to permissions")
			_, isJsonErr := permErr.Cause.(*json.UnmarshalTypeError)
			So(isJsonErr, ShouldBeTrue)
		},
	},
	{
		desc:           "there is an error reading the get permissions error response body",
		responseStatus: 500,
		body:           666,
		bodyErr:        errors.New("pow"),
		require:        CRUD{Create: true, Read: true, Update: true, Delete: true},
		assertErrorExpected: func(err error) {
			permErr, ok := err.(Error)
			So(ok, ShouldBeTrue)
			So(permErr.Status, ShouldEqual, 500)
			So(permErr.Message, ShouldEqual, "internal server error failed reading get permissions error response body")
			So(permErr.Cause, ShouldResemble, errors.New("pow"))
		},
	},
	{
		desc:           "there is an error reading the get permissions success response body",
		responseStatus: 200,
		body:           666,
		bodyErr:        errors.New("pow"),
		require:        CRUD{Create: true, Read: true, Update: true, Delete: true},
		assertErrorExpected: func(err error) {
			permErr, ok := err.(Error)
			So(ok, ShouldBeTrue)
			So(permErr.Status, ShouldEqual, 500)
			So(permErr.Message, ShouldEqual, "internal server error failed reading get permissions response body")
			So(permErr.Cause, ShouldResemble, errors.New("pow"))
		},
	},
	{
		desc:           "the get permissions response contain and unexpected error status",
		responseStatus: 418,
		body:           errorEntity{"I'm a teapot"},
		bodyErr:        nil,
		require:        CRUD{Create: true, Read: true, Update: true, Delete: true},
		assertErrorExpected: func(err error) {
			permErr, ok := err.(Error)
			So(ok, ShouldBeTrue)
			So(permErr.Status, ShouldEqual, 500)
			So(permErr.Message, ShouldEqual, "internal server error")
			So(permErr.Cause, ShouldBeNil)
		},
	},
}

// vetPermissionsTestCase is a struct representation of permissoins.Vet test case scenario
type vetPermissionsTestCase struct {
	desc                string
	responseStatus      int
	body                interface{}
	bodyErr             error
	responseErr         error
	require             CRUD
	serviceT            string
	userT               string
	collectionID        string
	assertErrorExpected func(err error)
}

func TestPermissions_Vet(t *testing.T) {

	for i, tc := range vertPermissionsTestCases {
		Convey(fmt.Sprintf("%d) Given %s", i, tc.desc), t, func() {

			// set up the mock client to return the test case response
			client := &mocks.HTTPClient{
				DoFunc: func() (response *http.Response, e error) {
					return tc.getClientResponse()
				},
			}
			// init permissions
			p := New("host", client)

			Convey("when permissions.Vet is called", func() {
				err := p.Vet(nil, tc.require, "", "", "", "")

				Convey("then the expected response is returned", func() {
					tc.assertErrorExpected(err)
				})
			})
		})
	}
}

func (tc vetPermissionsTestCase) getResponseBody() ([]byte, error) {
	b, _ := json.Marshal(tc.body)
	return b, tc.bodyErr
}

func (tc vetPermissionsTestCase) getClientResponse() (*http.Response, error) {
	r := &http.Response{
		StatusCode: tc.responseStatus,
		Body: &mocks.ReadCloser{
			GetEntityFunc: func() ([]byte, error) {
				return tc.getResponseBody()
			},
		},
	}
	return r, tc.responseErr
}
