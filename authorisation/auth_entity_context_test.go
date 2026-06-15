package authorisation_test

import (
	"context"
	"testing"

	"github.com/ONSdigital/dp-authorisation/v2/authorisation"
	permsdk "github.com/ONSdigital/dp-permissions-api/sdk"
	. "github.com/smartystreets/goconvey/convey"
)

const (
	testUserID = "test-user"
	testGroupA = "group-a"
)

func TestContextWithAuthEntityDataAndFromContext(t *testing.T) {
	Convey("Given auth entity data and a base context", t, func() {
		ctx := context.Background()
		expected := &authorisation.AuthEntityData{
			EntityData: &permsdk.EntityData{
				UserID: testUserID,
				Groups: []string{testGroupA},
			},
			IsServiceAuth: true,
		}

		Convey("When the auth entity data is added to context", func() {
			ctxWithData := authorisation.ContextWithAuthEntityData(ctx, expected)
			got, ok := authorisation.AuthEntityDataFromContext(ctxWithData)

			Convey("Then the same auth entity data is returned", func() {
				So(ok, ShouldBeTrue)
				So(got, ShouldEqual, expected)
			})
		})
	})
}

func TestAuthEntityDataFromContextWhenMissing(t *testing.T) {
	Convey("Given a context without auth entity data", t, func() {
		ctx := context.Background()

		Convey("When auth entity data is retrieved from context", func() {
			got, ok := authorisation.AuthEntityDataFromContext(ctx)

			Convey("Then no auth entity data is found", func() {
				So(ok, ShouldBeFalse)
				So(got, ShouldBeNil)
			})
		})
	})
}
