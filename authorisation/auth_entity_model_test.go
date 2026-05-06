package authorisation_test

import (
	"testing"

	"github.com/ONSdigital/dp-authorisation/v2/authorisation"
	permsdk "github.com/ONSdigital/dp-permissions-api/sdk"
	. "github.com/smartystreets/goconvey/convey"
)

func TestCreateAuthEntityData(t *testing.T) {
	Convey("Given entity data", t, func() {
		entityData := &permsdk.EntityData{
			UserID: "test-user",
			Groups: []string{"group-a", "group-b"},
		}

		Convey("When auth entity data is created for service auth", func() {
			got := authorisation.CreateAuthEntityData(entityData, true)

			Convey("Then auth entity data contains the expected values", func() {
				So(got, ShouldNotBeNil)
				So(got.EntityData, ShouldNotBeNil)
				So(got.EntityData.UserID, ShouldEqual, entityData.UserID)
				So(got.EntityData.Groups, ShouldResemble, entityData.Groups)
				So(got.IsServiceAuth, ShouldBeTrue)
			})
		})

		Convey("When auth entity data is created for user auth", func() {
			got := authorisation.CreateAuthEntityData(entityData, false)

			Convey("Then the service auth flag is false", func() {
				So(got, ShouldNotBeNil)
				So(got.IsServiceAuth, ShouldBeFalse)
			})
		})
	})
}
