package authorisation

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestPolicy_Satisfied(t *testing.T) {
	type scenario struct {
		given        string
		then         string
		required     *Policy
		actual       *Policy
		assertResult func(err error)
	}

	scenarios := []scenario{
		{
			given:    "required permissions: CRUD & caller permissions: R",
			then:     "verify should be unsuccessful",
			required: &Policy{Create: true, Read: true, Update: true, Delete: true},
			actual:   &Policy{Create: false, Read: true, Update: false, Delete: false},
			assertResult: func(err error) {
				So(err, ShouldResemble, Error{
					Status:  403,
					Message: "action forbidden caller does not process the required permissions",
				})
			},
		},
		{
			given:    "required permissions: R & caller permissions: R",
			then:     "verify should be successful",
			required: &Policy{Create: false, Read: true, Update: false, Delete: false},
			actual:   &Policy{Create: false, Read: true, Update: false, Delete: false},
			assertResult: func(err error) {
				So(err, ShouldBeNil)
			},
		},
		{
			given:    "required permissions: none & caller permissions: R",
			then:     "verify should be successful",
			required: &Policy{Create: false, Read: false, Update: false, Delete: false},
			actual:   &Policy{Create: false, Read: true, Update: false, Delete: false},
			assertResult: func(err error) {
				So(err, ShouldBeNil)
			},
		},
		{
			given:    "required permissions: CRUD & caller permissions: CRU",
			then:     "verify should be unsuccessful",
			required: &Policy{Create: true, Read: true, Update: true, Delete: true},
			actual:   &Policy{Create: true, Read: true, Update: true, Delete: false},
			assertResult: func(err error) {
				So(err, ShouldResemble, Error{
					Status:  403,
					Message: "action forbidden caller does not process the required permissions",
				})
			},
		},
		{
			given:    "required permissions: R & caller permissions: CRUD",
			then:     "verify should be successful",
			required: &Policy{Create: false, Read: true, Update: false, Delete: false},
			actual:   &Policy{Create: true, Read: true, Update: true, Delete: true},
			assertResult: func(err error) {
				So(err, ShouldBeNil)
			},
		},
		{
			given:    "required permissions: R & caller permissions: C",
			then:     "verify should be unsuccessful",
			required: &Policy{Create: false, Read: true, Update: false, Delete: false},
			actual:   &Policy{Create: true, Read: false, Update: false, Delete: false},
			assertResult: func(err error) {
				So(err, ShouldResemble, Error{
					Status:  403,
					Message: "action forbidden caller does not process the required permissions",
				})
			},
		},
	}

	for i, s := range scenarios {
		Convey(fmt.Sprintf("%d) Given %s ", i, s.given), t, func() {

			Convey("when the caller permissions are checked", func() {
				err := s.required.Satisfied(nil, s.actual)

				Convey("then the expected error should be returned", func() {
					s.assertResult(err)
				})
			})
		})
	}
}
