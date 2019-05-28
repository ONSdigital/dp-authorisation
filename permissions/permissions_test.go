package permissions

import (
	"fmt"
	"testing"

	"github.com/ONSdigital/go-ns/common"
	. "github.com/smartystreets/goconvey/convey"
)

func TestChecker_GetPermissionsRequestHostNotConfigured(t *testing.T) {
	Convey("Given the checker has not been configured with a host", t, func() {
		checker := &Checker{}

		Convey("When GetPermissionsRequest is called", func() {
			r, err := checker.getPermissionsRequest("", "", "", "")

			Convey("Then the expected error is returned", func() {
				So(err.Error(), ShouldEqual, "error creating permissions request host not configured")
			})

			Convey("And request is nil", func() {
				So(r, ShouldBeNil)
			})
		})
	})
}

func TestChecker__GetPermissionsRequestSuccess(t *testing.T) {
	Convey("Given a checker that has been configured", t, func() {
		permissionsURL := "http://localhost:8082/permissions"

		checker := Checker{host: permissionsURL}

		Convey("When GetPermissionsRequest is called", func() {
			r, err := checker.getPermissionsRequest("111", "222", "333", "444")

			Convey("Then the expected request is returned", func() {
				So(r.Header.Get(common.AuthHeaderKey), ShouldEqual, "111")
				So(r.Header.Get(common.FlorenceHeaderKey), ShouldEqual, "222")
				So(r.URL.Query().Get("collection_id"), ShouldEqual, "333")
				So(r.URL.Query().Get("dataset_id"), ShouldEqual, "444")
			})

			Convey("And error is nil", func() {
				So(err, ShouldBeNil)
			})
		})

	})
}

func TestCRUD_Check(t *testing.T) {
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
