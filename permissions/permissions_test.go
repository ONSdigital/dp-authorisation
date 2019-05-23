package permissions

import (
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
