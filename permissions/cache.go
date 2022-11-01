package permissions

import (
	"context"
	"sync"
	"time"

	health "github.com/ONSdigital/dp-healthcheck/healthcheck"
	permsdk "github.com/ONSdigital/dp-permissions-api/sdk"
	"github.com/ONSdigital/log.go/v2/log"
)

// Compiler check to ensure CachingStore implements the Store interface.
var _ Store = (*CachingStore)(nil)

// CachingStore is a permissions store implementation that caches permission data in memory.
type CachingStore struct {
	underlyingStore      Store
	cachedBundle         permsdk.Bundle
	closing              chan struct{}
	cacheUpdaterClosed   chan struct{}
	lastUpdated          time.Time
	lastUpdateSuccessful bool
	mutex                sync.Mutex
}

// NewCachingStore constructs a new instance of CachingStore
func NewCachingStore(underlyingStore Store) *CachingStore {
	return &CachingStore{
		underlyingStore:    underlyingStore,
		closing:            make(chan struct{}),
		cacheUpdaterClosed: make(chan struct{}),
	}
}

// GetPermissionsBundle returns the cached permission data, or an error if it's not cached.
func (c *CachingStore) GetPermissionsBundle(ctx context.Context) (permsdk.Bundle, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.cachedBundle == nil {
		return nil, permsdk.ErrNotCached
	}

	return c.cachedBundle, nil
}

// Update the permissions cache data, by calling the underlying permissions store
func (c *CachingStore) Update(ctx context.Context, maxCacheTime time.Duration) (permsdk.Bundle, error) {
	bundle, err := c.underlyingStore.GetPermissionsBundle(ctx)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if err != nil {
		c.lastUpdateSuccessful = false
		go func() {
			c.CheckCacheExpiry(ctx, maxCacheTime)
		}()
	} else {
		c.lastUpdateSuccessful = true
		c.cachedBundle = bundle
	}
	c.lastUpdated = time.Now()

	return bundle, err
}

// CheckCacheExpiry clears the cache data it it's gone beyond it's expiry time.
func (c *CachingStore) CheckCacheExpiry(ctx context.Context, maxCacheTime time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if time.Since(c.lastUpdated) > maxCacheTime {
		log.Info(ctx, "clearing permissions cache data as it has gone beyond the max cache time")
		c.cachedBundle = nil
		c.lastUpdated = time.Now()
	}
}

// StartCacheUpdater starts a go routine to continually update cache data at time intervals.
//   - updateInterval - how often to update the cache data.
func (c *CachingStore) StartCacheUpdater(ctx context.Context, updateInterval time.Duration, maxCacheTime time.Duration) {
	c.updateWithErrLog(ctx, maxCacheTime)
	go func() {
		defer close(c.cacheUpdaterClosed)
		startupTicker := time.NewTicker(time.Second * 30)
		initialisedTicker := time.NewTicker(updateInterval)
		for {
			select {
			case <-startupTicker.C:
				if c.cachedBundle == nil {
					c.updateWithErrLog(ctx, maxCacheTime)
				} else {
					startupTicker.Stop()
				}
			case <-initialisedTicker.C:
				c.updateWithErrLog(ctx, maxCacheTime)
			case <-c.closing:
				startupTicker.Stop()
				initialisedTicker.Stop()
				return
			case <-ctx.Done():
				c.Close(ctx)
			}
		}
	}()
}

// Close stops go routines and blocks until closed.
func (c *CachingStore) Close(ctx context.Context) error {
	close(c.closing)
	<-c.cacheUpdaterClosed
	return nil
}

func (c *CachingStore) HealthCheck(ctx context.Context, state *health.CheckState) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.cachedBundle == nil {
		return state.Update(health.StatusCritical, "permissions cache is empty", 0)
	}

	if !c.lastUpdateSuccessful {
		return state.Update(health.StatusWarning, "the last permissions cache update failed", 0)
	}

	return state.Update(health.StatusOK, "permissions cache is ok", 0)
}

func (c *CachingStore) updateWithErrLog(ctx context.Context, maxCacheTime time.Duration) {
	_, err := c.Update(ctx, maxCacheTime)
	if err != nil {
		log.Error(ctx, "failed to update permissions cache", err)
	}
}
