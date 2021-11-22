package permissions

import (
	"context"
	"sync"
	"time"

	health "github.com/ONSdigital/dp-healthcheck/healthcheck"
	"github.com/ONSdigital/log.go/v2/log"
)

// Compiler check to ensure CachingStore implements the Store interface.
var _ Store = (*CachingStore)(nil)

// CachingStore is a permissions store implementation that caches permission data in memory.
type CachingStore struct {
	underlyingStore      Store
	cachedBundle         Bundle
	closing              chan struct{}
	expiryCheckerClosed  chan struct{}
	cacheUpdaterClosed   chan struct{}
	lastUpdated          time.Time
	lastUpdateSuccessful bool
	mutex                sync.Mutex
}

// NewCachingStore constructs a new instance of CachingStore
func NewCachingStore(underlyingStore Store) *CachingStore {
	return &CachingStore{
		underlyingStore:     underlyingStore,
		closing:             make(chan struct{}),
		expiryCheckerClosed: make(chan struct{}),
		cacheUpdaterClosed:  make(chan struct{}),
	}
}

// GetPermissionsBundle returns the cached permission data, or an error if it's not cached.
func (c *CachingStore) GetPermissionsBundle(ctx context.Context) (Bundle, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.cachedBundle == nil {
		return nil, ErrNotCached
	}

	return c.cachedBundle, nil
}

// Update the permissions cache data, by calling the underlying permissions store
func (c *CachingStore) Update(ctx context.Context) (Bundle, error) {
	bundle, err := c.underlyingStore.GetPermissionsBundle(ctx)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if err != nil {
		c.lastUpdateSuccessful = false
	} else {
		c.lastUpdateSuccessful = true
		c.cachedBundle = bundle
	}
	c.lastUpdated = time.Now()

	return bundle, err
}

// StartExpiryChecker starts a goroutine to continually check for expired cache data.
//  - checkInterval - how often to check for expired cache data.
//  - maxCacheTime - how long to cache permissions data before it's expired.
func (c *CachingStore) StartExpiryChecker(ctx context.Context, checkInterval, maxCacheTime time.Duration) {
	go func() {
		defer close(c.expiryCheckerClosed)
		ticker := time.NewTicker(checkInterval)

		for {
			select {
			case <-ticker.C:
				c.CheckCacheExpiry(ctx, maxCacheTime)
			case <-c.closing:
				ticker.Stop()
				return
			case <-ctx.Done():
				c.Close(ctx)
			}
		}
	}()
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
//  - updateInterval - how often to update the cache data.
func (c *CachingStore) StartCacheUpdater(ctx context.Context, updateInterval time.Duration) {
	go func() {
		defer close(c.cacheUpdaterClosed)
		startupTicker := time.NewTicker(time.Second * 30)
		initialisedTicker := time.NewTicker(updateInterval)
		for {
			select {
			case <-startupTicker.C:
				if c.cachedBundle == nil {
					c.updateWithErrLog(ctx)
				} else {
					startupTicker.Stop()
				}
			case <-initialisedTicker.C:
				c.updateWithErrLog(ctx)
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
	<-c.expiryCheckerClosed
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

func (c *CachingStore) updateWithErrLog(ctx context.Context) {
	_, err := c.Update(ctx)
	if err != nil {
		log.Error(ctx, "failed to update permissions cache", err)
	}
}
