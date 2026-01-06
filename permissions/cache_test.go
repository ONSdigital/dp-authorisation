package permissions_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ONSdigital/dp-authorisation/v2/permissions"
	"github.com/ONSdigital/dp-authorisation/v2/permissions/mock"
	"github.com/ONSdigital/dp-healthcheck/healthcheck"
	permsdk "github.com/ONSdigital/dp-permissions-api/sdk"
	. "github.com/smartystreets/goconvey/convey"
)

var maxCacheTime = 1 * time.Minute

func TestCachingStore_Update(t *testing.T) {
	expectedBundle := permsdk.Bundle{}
	ctx := context.Background()
	underlyingStore := &mock.StoreMock{
		GetPermissionsBundleFunc: func(ctx context.Context, headers permsdk.Headers) (permsdk.Bundle, error) {
			return expectedBundle, nil
		},
	}

	Convey("Given a CachingStore with a mocked underlying store", t, func() {
		store := permissions.NewCachingStore(underlyingStore)

		Convey("When Update is called", func() {
			bundle, err := store.Update(ctx, maxCacheTime)

			Convey("Then no error is returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the expected permissions bundle is returned", func() {
				So(bundle, ShouldEqual, expectedBundle)
			})
		})
	})
}

func TestCachingStore_Update_UnderlyingStoreErr(t *testing.T) {
	expectedErr := errors.New("API broke")
	ctx := context.Background()
	underlyingStore := &mock.StoreMock{
		GetPermissionsBundleFunc: func(ctx context.Context, headers permsdk.Headers) (permsdk.Bundle, error) {
			return nil, expectedErr
		},
	}

	Convey("Given a CachingStore with a mocked underlying store", t, func() {
		store := permissions.NewCachingStore(underlyingStore)

		Convey("When Update is called", func() {
			bundle, err := store.Update(ctx, maxCacheTime)

			Convey("Then the expected error is returned", func() {
				So(err, ShouldEqual, expectedErr)
			})

			Convey("Then the permissions bundle is nil", func() {
				So(bundle, ShouldBeNil)
			})
		})
	})
}

func TestCachingStore_GetPermissionsBundle(t *testing.T) {
	expectedBundle := permsdk.Bundle{}
	ctx := context.Background()
	underlyingStore := &mock.StoreMock{
		GetPermissionsBundleFunc: func(ctx context.Context, headers permsdk.Headers) (permsdk.Bundle, error) {
			return expectedBundle, nil
		},
	}

	Convey("Given a CachingStore that has a cached permissions bundle", t, func() {
		store := permissions.NewCachingStore(underlyingStore)
		_, err := store.Update(ctx, maxCacheTime)
		So(err, ShouldBeNil)

		Convey("When GetPermissionsBundle is called", func() {
			bundle, err := store.GetPermissionsBundle(ctx, permsdk.Headers{})

			Convey("Then no error is returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the expected permissions bundle is returned", func() {
				So(bundle, ShouldEqual, expectedBundle)
			})
		})
	})
}

func TestCachingStore_GetPermissionsBundle_NotCached(t *testing.T) {
	ctx := context.Background()

	Convey("Given a CachingStore that does not have a cached permissions bundle", t, func() {
		store := permissions.NewCachingStore(&mock.StoreMock{})

		Convey("When GetPermissionsBundle is called", func() {
			bundle, err := store.GetPermissionsBundle(ctx, permsdk.Headers{})

			Convey("Then the expected error is returned", func() {
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, permsdk.ErrNotCached)
			})

			Convey("Then the permissions bundle is nil", func() {
				So(bundle, ShouldBeNil)
			})
		})
	})
}

func TestCachingStore_CheckCacheExpiry(t *testing.T) {
	ctx := context.Background()
	expectedBundle := permsdk.Bundle{}
	underlyingStore := &mock.StoreMock{
		GetPermissionsBundleFunc: func(ctx context.Context, headers permsdk.Headers) (permsdk.Bundle, error) {
			return expectedBundle, nil
		},
	}

	Convey("Given a CachingStore with cached data that's not expired", t, func() {
		store := permissions.NewCachingStore(underlyingStore)
		_, err := store.Update(ctx, maxCacheTime)
		So(err, ShouldBeNil)

		Convey("When CheckCacheExpiry is called", func() {
			store.CheckCacheExpiry(ctx, time.Second)

			Convey("Then there should still be cached data", func() {
				bundle, err := store.GetPermissionsBundle(ctx, permsdk.Headers{})
				So(bundle, ShouldEqual, expectedBundle)
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestCachingStore_CheckCacheExpiry_Expired(t *testing.T) {
	ctx := context.Background()
	expectedBundle := permsdk.Bundle{}
	underlyingStore := &mock.StoreMock{
		GetPermissionsBundleFunc: func(ctx context.Context, headers permsdk.Headers) (permsdk.Bundle, error) {
			return expectedBundle, nil
		},
	}

	Convey("Given a CachingStore with cached data that has expired", t, func() {
		store := permissions.NewCachingStore(underlyingStore)
		_, err := store.Update(ctx, maxCacheTime)
		So(err, ShouldBeNil)

		Convey("When CheckCacheExpiry is called", func() {
			store.CheckCacheExpiry(ctx, time.Nanosecond)
			time.Sleep(time.Millisecond)

			Convey("Then there should should be no cached data", func() {
				bundle, err := store.GetPermissionsBundle(ctx, permsdk.Headers{})
				So(err, ShouldEqual, permsdk.ErrNotCached)
				So(bundle, ShouldBeNil)
			})
		})
	})
}

func TestCachingStore_CheckCacheExpiry_NoCachedData(t *testing.T) {
	ctx := context.Background()
	underlyingStore := &mock.StoreMock{}

	Convey("Given a CachingStore with no cached data", t, func() {
		store := permissions.NewCachingStore(underlyingStore)

		Convey("When CheckCacheExpiry is called", func() {
			store.CheckCacheExpiry(ctx, time.Nanosecond)

			Convey("Then the expected ErrNotCached error should be returned", func() {
				bundle, err := store.GetPermissionsBundle(ctx, permsdk.Headers{})
				So(err, ShouldEqual, permsdk.ErrNotCached)
				So(bundle, ShouldBeNil)
			})
		})
	})
}

func TestCachingStore_HealthCheck_Critical(t *testing.T) {
	ctx := context.Background()

	Convey("Given a CachingStore with no cached data", t, func() {
		underlyingStore := &mock.StoreMock{}
		store := permissions.NewCachingStore(underlyingStore)

		Convey("When HealthCheck is called", func() {
			checkState := healthcheck.NewCheckState("")
			err := store.HealthCheck(ctx, checkState)

			Convey("Then no error is returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the health check state is set to critical", func() {
				So(checkState.Status(), ShouldEqual, healthcheck.StatusCritical)
				So(checkState.Message(), ShouldEqual, "permissions cache is empty")
			})
		})
	})
}

func TestCachingStore_HealthCheck_OK(t *testing.T) {
	ctx := context.Background()
	expectedBundle := permsdk.Bundle{}

	Convey("Given a CachingStore with cached data", t, func() {
		underlyingStore := &mock.StoreMock{
			GetPermissionsBundleFunc: func(ctx context.Context, headers permsdk.Headers) (permsdk.Bundle, error) {
				return expectedBundle, nil
			},
		}
		store := permissions.NewCachingStore(underlyingStore)
		_, err := store.Update(ctx, maxCacheTime)
		So(err, ShouldBeNil)

		Convey("When HealthCheck is called", func() {
			checkState := healthcheck.NewCheckState("")
			err := store.HealthCheck(ctx, checkState)

			Convey("Then no error is returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the health check state is set to OK", func() {
				So(checkState.Status(), ShouldEqual, healthcheck.StatusOK)
				So(checkState.Message(), ShouldEqual, "permissions cache is ok")
			})
		})
	})
}

func TestCachingStore_HealthCheck_Warning(t *testing.T) {
	ctx := context.Background()
	expectedBundle := permsdk.Bundle{}

	Convey("Given a CachingStore with cached data and a failed cache update", t, func() {
		hasBeenCalled := false
		expectedError := errors.New("permissions API call failed")
		underlyingStore := &mock.StoreMock{
			GetPermissionsBundleFunc: func(ctx context.Context, headers permsdk.Headers) (permsdk.Bundle, error) {
				if hasBeenCalled {
					return nil, expectedError
				}

				hasBeenCalled = true
				return expectedBundle, nil
			},
		}
		store := permissions.NewCachingStore(underlyingStore)

		_, err := store.Update(ctx, maxCacheTime) // first update succeeds to update cache
		So(err, ShouldBeNil)

		_, err = store.Update(ctx, maxCacheTime) // second update returns an error to imitate a failed update
		So(err, ShouldNotBeNil)

		Convey("When HealthCheck is called", func() {
			checkState := healthcheck.NewCheckState("")
			err := store.HealthCheck(ctx, checkState)

			Convey("Then no error is returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then the health check state is set to warning", func() {
				So(checkState.Status(), ShouldEqual, healthcheck.StatusWarning)
				So(checkState.Message(), ShouldEqual, "the last permissions cache update failed")
			})
		})
	})
}

func TestCachingStore_BackgroundGoRoutines(t *testing.T) {
	expectedBundle := permsdk.Bundle{}
	ctx := context.Background()
	underlyingStore := &mock.StoreMock{
		GetPermissionsBundleFunc: func(ctx context.Context, headers permsdk.Headers) (permsdk.Bundle, error) {
			return expectedBundle, nil
		},
	}

	Convey("Given a CachingStore the background go routines started", t, func() {
		store := permissions.NewCachingStore(underlyingStore)
		store.StartCacheUpdater(ctx, time.Second, maxCacheTime)

		Convey("When Close is called", func() {
			err := store.Close(ctx)

			Convey("Then no error is returned", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When the permissions bundle is ", func() {
			_, err := store.GetPermissionsBundle(ctx, permsdk.Headers{})

			Convey("Then no error is returned", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}
