package permissions

import (
	"context"
)

//go:generate moq -out mock/store.go -pkg mock . Store
//go:generate moq -out mock/cache.go -pkg mock . Cache

// Store represents a store of permission data
// The implementation can be a client of the permissions API, though a cache implementation can also be wrapped around it.
type Store interface {
	GetPermissionsBundle(ctx context.Context) (*Bundle, error)
}

// Cache represents a cache of permissions data.
type Cache interface {
	Store
	Close(ctx context.Context) error
}
