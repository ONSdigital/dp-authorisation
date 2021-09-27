package permissions_test

import (
	"context"
	"github.com/ONSdigital/dp-authorisation/v2/permissions"
	"github.com/ONSdigital/dp-authorisation/v2/permissions/mock"
	"github.com/ONSdigital/dp-healthcheck/healthcheck"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

var permissionsBundle = &permissions.Bundle{
	PermissionToEntityLookup: map[string]permissions.EntityIDToPolicies{
		"users.add": map[string][]permissions.Policy{
			"group/admin": {
				permissions.Policy{
					PolicyID:   "policy1",
					Conditions: nil,
				},
			},
		},
		"legacy.read": map[string][]permissions.Policy{
			"group/admin": {
				permissions.Policy{
					PolicyID:   "policy3",
					Conditions: []permissions.Condition{},
				},
			},
			"group/publisher": {
				permissions.Policy{
					PolicyID:   "policy4",
					Conditions: []permissions.Condition{},
				},
			},
			"group/viewer": {
				permissions.Policy{
					PolicyID: "policy2",
					Conditions: []permissions.Condition{
						{
							Attributes: []string{"collection_id"},
							Operator:   "=",
							Values:     []string{"collection765"},
						},
						{
							Attributes: []string{"collection_id"},
							Operator:   "=",
							Values:     []string{"collection766"},
						},
						{
							Attributes: []string{"collection_id"},
							Operator:   "=",
							Values:     []string{"collection767"},
						},
					},
				},
			},
		},
		"legacy.write": map[string][]permissions.Policy{
			"group/admin": {
				permissions.Policy{
					PolicyID:   "policy5",
					Conditions: []permissions.Condition{},
				},
			},
			"group/publisher": {
				permissions.Policy{
					PolicyID:   "policy6",
					Conditions: []permissions.Condition{},
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
		entityData := permissions.EntityData{
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
		entityData := permissions.EntityData{
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
		entityData := permissions.EntityData{
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

func TestChecker_HasPermission_WithConditionTrue(t *testing.T) {
	ctx := context.Background()
	store := newMockCache()
	checker := permissions.NewCheckerForStore(store)

	Convey("Given a viewer user", t, func() {
		entityData := permissions.EntityData{
			Groups: []string{"viewer"},
		}

		Convey("When HasPermission is called with a collection ID that satisfies the policy condition", func() {
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

func TestChecker_HasPermission_MultipleConditionsChecked(t *testing.T) {
	ctx := context.Background()
	store := newMockCache()
	checker := permissions.NewCheckerForStore(store)

	Convey("Given a viewer user", t, func() {
		entityData := permissions.EntityData{
			Groups: []string{"viewer"},
		}

		Convey("When HasPermission is called with a collection ID that satisfies the last policy condition", func() {
			attributes := map[string]string{"collection_id": "collection767"}
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

func TestChecker_HasPermission_WithConditionFalse(t *testing.T) {
	ctx := context.Background()
	store := newMockCache()
	checker := permissions.NewCheckerForStore(store)

	Convey("Given a viewer user", t, func() {
		entityData := permissions.EntityData{
			Groups: []string{"viewer"},
		}

		Convey("When HasPermission is called with a collection ID that does not satisfy a policy condition", func() {
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
		GetPermissionsBundleFunc: func(ctx context.Context) (*permissions.Bundle, error) {
			return permissionsBundle, nil
		},
		CloseFunc: func(ctx context.Context) error {
			return nil
		},
		HealthCheckFunc: func(ctx context.Context, state *healthcheck.CheckState) error {
			return nil
		},
	}
}
