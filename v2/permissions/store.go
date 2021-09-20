package permissions

import "context"

// Store represents a store of permission data
// The implementation can be a client of the permissions API, though a cache implementation can also be wrapped around it.
type Store interface {
	GetPermissionsBundle(ctx context.Context) (*Bundle, error)
}
