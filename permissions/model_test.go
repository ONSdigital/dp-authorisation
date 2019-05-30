package permissions

import (
	"fmt"
	"reflect"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestCRUD_Satisfied(t *testing.T) {
	type scenario struct {
		given        string
		then         string
		required     *CRUD
		actual       *CRUD
		assertResult func(err error) bool
	}

	scenarios := []scenario{
		{
			given:    "required permissions: CRUD & caller permissions: R",
			then:     "verify should be unsuccessful",
			required: &CRUD{Create: true, Read: true, Update: true, Delete: true},
			actual:   &CRUD{Create: false, Read: true, Update: false, Delete: false},
			assertResult: func(err error) bool {
				return reflect.DeepEqual(err, Error{
					Status:  403,
					Message: "caller does not have the required permission to perform the requested action",
				})
			},
		},
		{
			given:    "required permissions: R & caller permissions: R",
			then:     "verify should be successful",
			required: &CRUD{Create: false, Read: true, Update: false, Delete: false},
			actual:   &CRUD{Create: false, Read: true, Update: false, Delete: false},
			assertResult: func(err error) bool {
				return err == nil
			},
		},
		{
			given:    "required permissions: none & caller permissions: R",
			then:     "verify should be successful",
			required: &CRUD{Create: false, Read: false, Update: false, Delete: false},
			actual:   &CRUD{Create: false, Read: true, Update: false, Delete: false},
			assertResult: func(err error) bool {
				return err == nil
			},
		},
		{
			given:    "required permissions: CRUD & caller permissions: CRU",
			then:     "verify should be unsuccessful",
			required: &CRUD{Create: true, Read: true, Update: true, Delete: true},
			actual:   &CRUD{Create: true, Read: true, Update: true, Delete: false},
			assertResult: func(err error) bool {
				return reflect.DeepEqual(err, Error{
					Status:  403,
					Message: "caller does not have the required permission to perform the requested action",
				})
			},
		},
		{
			given:    "required permissions: R & caller permissions: CRUD",
			then:     "verify should be successful",
			required: &CRUD{Create: false, Read: true, Update: false, Delete: false},
			actual:   &CRUD{Create: true, Read: true, Update: true, Delete: true},
			assertResult: func(err error) bool {
				return err == nil
			},
		},
		{
			given:    "required permissions: R & caller permissions: C",
			then:     "verify should be unsuccessful",
			required: &CRUD{Create: false, Read: true, Update: false, Delete: false},
			actual:   &CRUD{Create: true, Read: false, Update: false, Delete: false},
			assertResult: func(err error) bool {
				return reflect.DeepEqual(err, Error{
					Status:  403,
					Message: "caller does not have the required permission to perform the requested action",
				})
			},
		},
	}

	for i, s := range scenarios {
		Convey(fmt.Sprintf("%d) Given %s ", i, s.given), t, func() {

			Convey("when the caller permissions are checked", func() {
				err := s.required.Satisfied(nil, s.actual)

				Convey("then the expected error should be returned", func() {
					So(s.assertResult(err), ShouldBeTrue)
				})
			})
		})
	}
}
