package permissions_test

import (
	"context"
	"errors"
	"github.com/ONSdigital/dp-authorisation/v2/permissions"
	"github.com/ONSdigital/dp-authorisation/v2/permissions/mock"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
	"time"
)

func TestCachingStore_Update(t *testing.T) {
	expectedBundle := &permissions.Bundle{}
	ctx := context.Background()
	underlyingStore := &mock.StoreMock{
		GetPermissionsBundleFunc: func(ctx context.Context) (*permissions.Bundle, error) {
			return expectedBundle, nil
		},
	}

	Convey("Given a CachingStore with a mocked underlying store", t, func() {
		store := permissions.NewCachingStore(underlyingStore)

		Convey("When Update is called", func() {
			bundle, err := store.Update(ctx)

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
		GetPermissionsBundleFunc: func(ctx context.Context) (*permissions.Bundle, error) {
			return nil, expectedErr
		},
	}

	Convey("Given a CachingStore with a mocked underlying store", t, func() {
		store := permissions.NewCachingStore(underlyingStore)

		Convey("When Update is called", func() {
			bundle, err := store.Update(ctx)

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
	expectedBundle := &permissions.Bundle{}
	ctx := context.Background()
	underlyingStore := &mock.StoreMock{
		GetPermissionsBundleFunc: func(ctx context.Context) (*permissions.Bundle, error) {
			return expectedBundle, nil
		},
	}

	Convey("Given a CachingStore that has a cached permissions bundle", t, func() {
		store := permissions.NewCachingStore(underlyingStore)
		store.Update(ctx)

		Convey("When GetPermissionsBundle is called", func() {
			bundle, err := store.GetPermissionsBundle(ctx)

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
			bundle, err := store.GetPermissionsBundle(ctx)

			Convey("Then the expected error is returned", func() {
				So(err, ShouldNotBeNil)
				So(err, ShouldEqual, permissions.ErrNotCached)
			})

			Convey("Then the permissions bundle is nil", func() {
				So(bundle, ShouldBeNil)
			})
		})
	})
}

func TestCachingStore_CheckCacheExpiry(t *testing.T) {
	ctx := context.Background()
	expectedBundle := &permissions.Bundle{}
	underlyingStore := &mock.StoreMock{
		GetPermissionsBundleFunc: func(ctx context.Context) (*permissions.Bundle, error) {
			return expectedBundle, nil
		},
	}

	Convey("Given a CachingStore with cached data that's not expired", t, func() {
		store := permissions.NewCachingStore(underlyingStore)
		store.Update(ctx)

		Convey("When CheckCacheExpiry is called", func() {
			store.CheckCacheExpiry(ctx, time.Second)

			Convey("Then there should still be cached data", func() {
				bundle, err := store.GetPermissionsBundle(ctx)
				So(bundle, ShouldEqual, expectedBundle)
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestCachingStore_CheckCacheExpiry_Expired(t *testing.T) {
	ctx := context.Background()
	expectedBundle := &permissions.Bundle{}
	underlyingStore := &mock.StoreMock{
		GetPermissionsBundleFunc: func(ctx context.Context) (*permissions.Bundle, error) {
			return expectedBundle, nil
		},
	}

	Convey("Given a CachingStore with cached data that has expired", t, func() {
		store := permissions.NewCachingStore(underlyingStore)
		store.Update(ctx)

		Convey("When CheckCacheExpiry is called", func() {
			store.CheckCacheExpiry(ctx, time.Nanosecond)
			time.Sleep(time.Millisecond)

			Convey("Then there should should be no cached data", func() {
				bundle, err := store.GetPermissionsBundle(ctx)
				So(err, ShouldEqual, permissions.ErrNotCached)
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
				bundle, err := store.GetPermissionsBundle(ctx)
				So(err, ShouldEqual, permissions.ErrNotCached)
				So(bundle, ShouldBeNil)
			})
		})
	})
}
