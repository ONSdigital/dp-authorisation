package authv2

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

type checkAuthTestCase struct {
	scenario   string
	actual     *Permissions
	required   *Permissions
	assertFunc func(err error)
}

var checkAuthTestCases = []checkAuthTestCase{
	{
		scenario: "given caller permissions CRUD and required CRUD",
		actual:   &Permissions{Create: true, Read: true, Update: true, Delete: true},
		required: &Permissions{Create: true, Read: true, Update: true, Delete: true},
		assertFunc: func(err error) {
			So(err, ShouldBeNil)
		},
	},
	{
		scenario: "given caller permissions R and required CRUD",
		actual:   &Permissions{Read: true},
		required: &Permissions{Create: true, Read: true, Update: true, Delete: true},
		assertFunc: func(err error) {
			So(err, ShouldResemble, callerForbiddenError)
		},
	},
	{
		scenario: "given caller permissions CRUD and required C",
		actual:   &Permissions{Create: true, Read: true, Update: true, Delete: true},
		required: &Permissions{Create: true},
		assertFunc: func(err error) {
			So(err, ShouldBeNil)
		},
	},
	{
		scenario: "given caller permissions CRUD and required nil",
		actual:   &Permissions{Create: true, Read: true, Update: true, Delete: true},
		required: nil,
		assertFunc: func(err error) {
			So(err, ShouldBeNil)
		},
	},
	{
		scenario: "given caller permissions nil and required nil",
		actual:   nil,
		required: nil,
		assertFunc: func(err error) {
			So(err, ShouldBeNil)
		},
	},
	{
		scenario: "given caller permissions nil and required CRUD",
		actual:   nil,
		required: &Permissions{Create: true, Read: true, Update: true, Delete: true},
		assertFunc: func(err error) {
			So(err, ShouldResemble, callerForbiddenError)
		},
	},
}

func TestPermissionsVerifier_CheckAuthorisation(t *testing.T) {
	verifier := &PermissionsVerifier{}

	for i, tc := range checkAuthTestCases {
		givenStmt := fmt.Sprintf("%d/%d) %s", i+1, len(checkAuthTestCases), tc.scenario)

		Convey(givenStmt, t, func() {
			err := verifier.CheckAuthorisation(nil, tc.actual, tc.required)
			tc.assertFunc(err)
		})
	}
}
