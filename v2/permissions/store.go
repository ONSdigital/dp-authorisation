package permissions

import "context"

//go:generate moq -out mock/store.go -pkg mock . Store

// Store represents a store of permission data
// The implementation can be a client of the permissions API, though a cache implementation can also be wrapped around it.
type Store interface {
	GetPermissionsBundle(ctx context.Context) (*Bundle, error)
	Close(ctx context.Context) error
}
