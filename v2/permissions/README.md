
# Permissions library

The permissions library determines whether a user has a particular permission. It can be used within middleware to apply permissions to an entire endpoint, or can be used within a handler for more fine grained permissions.

The library polls the permissions API in the background for permissions updates and keeps an in memory cache of the data for a set period of time.

### Example Usage

Create a new instance of permissions.Checker:

```go
  import (
	"github.com/ONSdigital/dp-authorisation/v2/permissions"
  )
  
  ...
  
  permissionsAPIHost := "localhost:25400"
  cacheUpdateInterval := time.Minute
  expiryCheckInterval := time.Second * 5
  maxCacheTime := time.Minute * 5
	
  permissions.NewChecker(ctx, permissionsAPIHost, cacheUpdateInterval, expiryCheckInterval, maxCacheTime)
```
Parameter values should come from configuration. The example values have been left in for clarity.
- permissionsAPIHost: the hostname of the permissions API
- cacheUpdateInterval: how long between updates of the permissions cache
- expiryCheckInterval: how long between checks for expired cache data 
- maxCacheTime: how long before the permissions cache data should be expired

Check if a user has a permission

```go
  entityData := permissions.EntityData{
    UserID: "1234",
    Groups: []string{"admin"},
  }
  permission := "legacy.read"
  attributes := map[string]string{"collection_id": "collection123"}

  hasPermission, err := permissionChecker.HasPermission(ctx, entityData, permission, attributes)
  if err != nil {
    return 
  }
```

### Low level detail

- permissions.Checker: retrieves permission data from the store, and determines if a user has a permission.
- permissions.Store: interface used by the checker to retrieve permission data.
- permissions.APIClient: Store implementation to get data from the permissions API.
- permissions.CachingStore: Store implementation wraps another store (i.e. the APIClient) and caches permission data in memory.
  - polls the underlying store in the background to update cache data.
  - expires cache data if it reaches a certain age.
