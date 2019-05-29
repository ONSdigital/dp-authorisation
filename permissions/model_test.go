package permissions

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestCRUD_Satisfied(t *testing.T) {
	type scenario struct {
		given          string
		then           string
		required       *CRUD
		actual         *CRUD
		expectedResult bool
	}

	scenarios := []scenario{
		{
			given:          "required permissions: CRUD & caller permissions: R",
			then:           "verify should be unsuccessful",
			required:       &CRUD{Create: true, Read: true, Update: true, Delete: true},
			actual:         &CRUD{Create: false, Read: true, Update: false, Delete: false},
			expectedResult: false,
		},
		{
			given:          "required permissions: R & caller permissions: R",
			then:           "verify should be successful",
			required:       &CRUD{Create: false, Read: true, Update: false, Delete: false},
			actual:         &CRUD{Create: false, Read: true, Update: false, Delete: false},
			expectedResult: true,
		},
		{
			given:          "required permissions: none & caller permissions: R",
			then:           "verify should be successful",
			required:       &CRUD{Create: false, Read: false, Update: false, Delete: false},
			actual:         &CRUD{Create: false, Read: true, Update: false, Delete: false},
			expectedResult: true,
		},
		{
			given:          "required permissions: CRUD & caller permissions: CRU",
			then:           "verify should be unsuccessful",
			required:       &CRUD{Create: true, Read: true, Update: true, Delete: true},
			actual:         &CRUD{Create: true, Read: true, Update: true, Delete: false},
			expectedResult: false,
		},
		{
			given:          "required permissions: R & caller permissions: CRUD",
			then:           "verify should be successful",
			required:       &CRUD{Create: false, Read: true, Update: false, Delete: false},
			actual:         &CRUD{Create: true, Read: true, Update: true, Delete: true},
			expectedResult: true,
		},
		{
			given:          "required permissions: R & caller permissions: C",
			then:           "verify should be unsuccessful",
			required:       &CRUD{Create: false, Read: true, Update: false, Delete: false},
			actual:         &CRUD{Create: true, Read: false, Update: false, Delete: false},
			expectedResult: false,
		},
	}

	for i, s := range scenarios {
		Convey(fmt.Sprintf("%d) Given %s ", i, s.given), t, func() {
			outcome := "successful"
			if s.expectedResult {
				outcome = "successful"
			}

			Convey(fmt.Sprintf("Then verify should be %s", outcome), func() {
				So(s.required.Satisfied(nil, s.actual), ShouldEqual, s.expectedResult)
			})
		})
	}
}
