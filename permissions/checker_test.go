package permissions_test

import (
	"context"
	"testing"

	"github.com/ONSdigital/dp-authorisation/v2/permissions"
	"github.com/ONSdigital/dp-authorisation/v2/permissions/mock"
	"github.com/ONSdigital/dp-healthcheck/healthcheck"
	permsdk "github.com/ONSdigital/dp-permissions-api/sdk"
	. "github.com/smartystreets/goconvey/convey"
)

var permissionsBundle = permsdk.Bundle{
	"users.add": map[string][]permsdk.Policy{
		"groups/admin": {
			permsdk.Policy{
				ID:        "policy1",
				Condition: permsdk.Condition{},
			},
		},
	},
	"legacy.read": map[string][]permsdk.Policy{
		"groups/admin": {
			permsdk.Policy{
				ID:        "policy3",
				Condition: permsdk.Condition{},
			},
		},
		"groups/publisher": {
			permsdk.Policy{
				ID:        "policy4",
				Condition: permsdk.Condition{},
			},
		},
		"groups/viewer": {
			permsdk.Policy{
				ID: "policy2",
				Condition: permsdk.Condition{
					Attribute: "collection_id",
					Operator:  permsdk.OperatorStringEquals,
					Values:    []string{"collection765"},
				},
			},
		},
	},
	"legacy.write": map[string][]permsdk.Policy{
		"groups/admin": {
			permsdk.Policy{
				ID:        "policy5",
				Condition: permsdk.Condition{},
			},
		},
		"groups/publisher": {
			permsdk.Policy{
				ID:        "policy6",
				Condition: permsdk.Condition{},
			},
		},
	},
	"some_service.write": map[string][]permsdk.Policy{
		"groups/publisher": {
			permsdk.Policy{
				ID: "policy7",
				Condition: permsdk.Condition{
					Attribute: "path",
					Operator:  permsdk.OperatorStartsWith,
					Values:    []string{"/files/dir/a/"},
				},
			},
		},
	},
}

func TestChecker_HasPermission(t *testing.T) {
	ctx := context.Background()
	store := newMockCache()
	checker := permissions.NewCheckerForStore(store)

	Convey("Given an admin user", t, func() {
		entityData := permsdk.EntityData{
			Groups: []string{"admin"},
		}

		Convey("When HasPermission is called for a permission an admin has", func() {
			hasPermission, err := checker.HasPermission(ctx, entityData, "users.add", nil)

			Convey("Then there is no error returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the result is true", func() {
				So(hasPermission, ShouldBeTrue)
			})
		})
	})
}

func TestChecker_HasPermission_False(t *testing.T) {
	ctx := context.Background()
	store := newMockCache()
	checker := permissions.NewCheckerForStore(store)

	Convey("Given a publisher user", t, func() {
		entityData := permsdk.EntityData{
			Groups: []string{"publisher"},
		}

		Convey("When HasPermission is called for a permission a publisher does not have", func() {
			hasPermission, err := checker.HasPermission(ctx, entityData, "users.add", nil)

			Convey("Then there is no error returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the result is false", func() {
				So(hasPermission, ShouldBeFalse)
			})
		})
	})
}

func TestChecker_HasPermission_NoGroupMatch(t *testing.T) {
	ctx := context.Background()
	store := newMockCache()
	checker := permissions.NewCheckerForStore(store)

	Convey("Given a user that belongs to a group with no permissions", t, func() {
		entityData := permsdk.EntityData{
			Groups: []string{"default"},
		}

		Convey("When HasPermission is called", func() {
			hasPermission, err := checker.HasPermission(ctx, entityData, "legacy.read", nil)

			Convey("Then there is no error returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the result is false", func() {
				So(hasPermission, ShouldBeFalse)
			})
		})
	})
}

func TestChecker_HasPermission_WithStringEqualsConditionTrue(t *testing.T) {
	ctx := context.Background()
	store := newMockCache()
	checker := permissions.NewCheckerForStore(store)

	Convey("Given a viewer user", t, func() {
		entityData := permsdk.EntityData{
			Groups: []string{"viewer"},
		}

		Convey("When HasPermission is called with a collection ID that satisfies the 'StringEquals' policy condition", func() {
			attributes := map[string]string{"collection_id": "collection765"}

			hasPermission, err := checker.HasPermission(ctx, entityData, "legacy.read", attributes)

			Convey("Then there is no error returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the result is true", func() {
				So(hasPermission, ShouldBeTrue)
			})
		})
	})
}

func TestChecker_HasPermission_WithStringEqualsConditionFalse(t *testing.T) {
	ctx := context.Background()
	store := newMockCache()
	checker := permissions.NewCheckerForStore(store)

	Convey("Given a viewer user", t, func() {
		entityData := permsdk.EntityData{
			Groups: []string{"viewer"},
		}

		Convey("When HasPermission is called with a collection ID that does not satisfy a 'StringEquals' policy condition", func() {
			attributes := map[string]string{"collection_id": "collection999"}

			hasPermission, err := checker.HasPermission(ctx, entityData, "legacy.read", attributes)

			Convey("Then there is no error returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the result is false", func() {
				So(hasPermission, ShouldBeFalse)
			})
		})
	})
}

func TestChecker_HasPermission_WithCaseInsensitivePolicyConditionOperatorFalse(t *testing.T) {
	ctx := context.Background()
	store := newMockCache()
	checker := permissions.NewCheckerForStore(store)

	Convey("Given a viewer user", t, func() {
		entityData := permsdk.EntityData{
			Groups: []string{"viewer"},
		}

		Convey("When HasPermission is called with a collection ID that satisfies an invalid (case-insensitive) 'stringequals' policy condition operator", func() {
			attributes := map[string]string{"collection_id": "collection768"}

			hasPermission, err := checker.HasPermission(ctx, entityData, "legacy.read", attributes)

			Convey("Then there is no error returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the result is false", func() {
				So(hasPermission, ShouldBeFalse)
			})
		})
	})
}

func TestChecker_HasPermission_WithStartsWithConditionTrue(t *testing.T) {
	ctx := context.Background()
	store := newMockCache()
	checker := permissions.NewCheckerForStore(store)

	Convey("Given a publisher user", t, func() {
		entityData := permsdk.EntityData{
			Groups: []string{"publisher"},
		}

		Convey("When HasPermission is called with a collection ID that satisfies the 'StartsWith' policy condition", func() {
			attributes := map[string]string{"path": "/files/dir/a/some/dir/"}

			hasPermission, err := checker.HasPermission(ctx, entityData, "some_service.write", attributes)

			Convey("Then there is no error returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the result is true", func() {
				So(hasPermission, ShouldBeTrue)
			})
		})
	})
}

func TestChecker_HasPermission_WithStartsWithConditionFalse(t *testing.T) {
	ctx := context.Background()
	store := newMockCache()
	checker := permissions.NewCheckerForStore(store)

	Convey("Given a publisher user", t, func() {
		entityData := permsdk.EntityData{
			Groups: []string{"publisher"},
		}

		Convey("When HasPermission is called with a collection ID that does not satisfy the 'StartsWith' policy condition", func() {
			attributes := map[string]string{"path": "/files/dir/c/some/dir/"}

			hasPermission, err := checker.HasPermission(ctx, entityData, "some_service.write", attributes)

			Convey("Then there is no error returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the result is false", func() {
				So(hasPermission, ShouldBeFalse)
			})
		})
	})
}

func TestChecker_HasPermission_MultipleConditionsChecked(t *testing.T) {
	ctx := context.Background()
	store := newMockCache()
	checker := permissions.NewCheckerForStore(store)

	Convey("Given a viewer user", t, func() {
		entityData := permsdk.EntityData{
			Groups: []string{"viewer"},
		}

		Convey("When HasPermission is called with a collection ID that satisfies the last 'StringEquals' policy condition", func() {
			attributes := map[string]string{"collection_id": "collection765"}

			hasPermission, err := checker.HasPermission(ctx, entityData, "legacy.read", attributes)

			Convey("Then there is no error returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the result is true", func() {
				So(hasPermission, ShouldBeTrue)
			})
		})
	})
}

func TestChecker_Close(t *testing.T) {
	ctx := context.Background()

	Convey("Given a checker with a mock store", t, func() {
		store := newMockCache()
		checker := permissions.NewCheckerForStore(store)

		Convey("When Close is called", func() {
			err := checker.Close(ctx)

			Convey("Then no error is returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then close is called on the permissions store", func() {
				So(store.CloseCalls(), ShouldHaveLength, 1)
			})
		})
	})
}

func TestChecker_HealthCheck(t *testing.T) {
	ctx := context.Background()

	Convey("Given a checker with a mock store", t, func() {
		store := newMockCache()
		checker := permissions.NewCheckerForStore(store)

		Convey("When Close is called", func() {
			expectedCheckState := &healthcheck.CheckState{}
			err := checker.HealthCheck(ctx, expectedCheckState)

			Convey("Then no error is returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then close is called on the permissions store", func() {
				So(store.HealthCheckCalls(), ShouldHaveLength, 1)
				So(store.HealthCheckCalls()[0].State, ShouldEqual, expectedCheckState)
			})
		})
	})
}

func newMockCache() *mock.CacheMock {
	return &mock.CacheMock{
		GetPermissionsBundleFunc: func(_ context.Context) (permsdk.Bundle, error) {
			return permissionsBundle, nil
		},
		CloseFunc: func(_ context.Context) error {
			return nil
		},
		HealthCheckFunc: func(_ context.Context, state *healthcheck.CheckState) error {
			return nil
		},
	}
}
