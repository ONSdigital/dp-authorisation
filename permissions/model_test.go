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
			given:          "required permissionsList: CRUD & caller permissionsList: R",
			then:           "verify should be unsuccessful",
			required:       &CRUD{Create: true, Read: true, Update: true, Delete: true},
			actual:         &CRUD{Create: false, Read: true, Update: false, Delete: false},
			expectedResult: false,
		},
		{
			given:          "required permissionsList: R & caller permissionsList: R",
			then:           "verify should be successful",
			required:       &CRUD{Create: false, Read: true, Update: false, Delete: false},
			actual:         &CRUD{Create: false, Read: true, Update: false, Delete: false},
			expectedResult: true,
		},
		{
			given:          "required permissionsList: none & caller permissionsList: R",
			then:           "verify should be successful",
			required:       &CRUD{Create: false, Read: false, Update: false, Delete: false},
			actual:         &CRUD{Create: false, Read: true, Update: false, Delete: false},
			expectedResult: true,
		},
		{
			given:          "required permissionsList: CRUD & caller permissionsList: CRU",
			then:           "verify should be unsuccessful",
			required:       &CRUD{Create: true, Read: true, Update: true, Delete: true},
			actual:         &CRUD{Create: true, Read: true, Update: true, Delete: false},
			expectedResult: false,
		},
		{
			given:          "required permissionsList: R & caller permissionsList: CRUD",
			then:           "verify should be successful",
			required:       &CRUD{Create: false, Read: true, Update: false, Delete: false},
			actual:         &CRUD{Create: true, Read: true, Update: true, Delete: true},
			expectedResult: true,
		},
		{
			given:          "required permissionsList: R & caller permissionsList: C",
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
