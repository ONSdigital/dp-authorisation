
# dp-authorisation V2

Authorisation is broken down into two parts:
- JWT token parsing: read the `Authorization` header of a request, and parse the JWT token contained in it. From the JWT token the user ID and list of groups the user belongs to is extracted and returned in the `EntityData` type. This functionality is within the `jwt` package. See the [package readme for more details](jwt/README.md)
- Permissions check - the action that the user is taking will have a permission associated with it. The permissions check does a lookup to see if the requested permission is granted to the user, or the groups that the user belongs to. This functionality is within the `permissions` package. See the [package readme for more details](permissions/README.md)

### Usage
The permission check will typically be wrapped around an entire endpoint via middleware, but it can also be checked within a handler with more complex logic if needed.

#### Authorisation config
The config values for authorisation are the same regardless of how authorisation is applied to a service. The authorisation package provides a configuration type that can be embedded within an existing service config type.

```go
  type Config struct {
	...
	AuthorisationConfig *authorisation.Config
  }
```

A set of default configuration values can be retrieved using the `authorisation.NewDefaultConfig()` function. These can be used for local development and testing. The config values should be set as environment variables when running in an environment.

#### Option 1 - Add authorisation middleware to API endpoints

For the typical case of adding authorisation as middleware, the JWT parsing and permissions checking has been bundled into a single `Middleware` type.

##### Create a new instance of authorisation middleware
```go
    authorisationMiddleware, err := authorisation.NewFeatureFlaggedMiddleware(ctx, authorisationConfig)
```

Using the `NewFeatureFlaggedMiddleware` constructor will use the `Enabled` config value to automatically apply a feature flag to authorisation. If the flag is disabled, a no-op instance of middleware will be used. This minimises the amount of code required to apply a feature flag to authorisation. Endpoints can still be wrapped with the authorisation middleware, but it will just act as a pass through if authorisation is disabled. Should you want to create a middleware instance without a feature flag, use the `NewMiddlewareFromConfig` constructor function instead.

##### Wrap endpoints using the `authorisationMiddleware.Require` function
```go
    r.HandleFunc("/v1/users", authorisationMiddleware.Require("users:create", api.CreateUserHandler)).Methods(http.MethodPost)
```
The above example shows the POST /users endpoint being wrapped with authorisation middleware, requiring the caller to have the `users:create` permission.

##### Add a health check for the underlying permissions checker
```go
    if err := hc.AddCheck("permissions cache health check", authorisationMiddleware.HealthCheck); err != nil {
        hasErrors = true
        log.Error(ctx, "error adding check for permissions cache", err)
    }
```

##### Call close on the middleware instance when the service is shut down
```go
   if err := svc.authorisationMiddleware.Close(ctx); err != nil {
        log.Error(ctx, "failed to close authorisation middleware", err)
        hasShutdownError = true
    }
```

##### Creating a mock middleware instance for unit testing

A mock for the `Middleware` interface is available for unit testing:
```go
    import (
        authorisation "github.com/ONSdigital/dp-authorisation/v2/authorisation/mock"
    )
    
    ...

    middlewareMock := &authorisation.MiddlewareMock{
        RequireFunc: func(permission string, handlerFunc http.HandlerFunc) http.HandlerFunc {
            return handlerFunc
        },
    }
```

#### Option 2 - Add authorisation within a handler (not via middleware)

If the authorisation for a service requires something more complex than middleware around a handler, the implementation will depend on the services particular requirements. Though it will still come down to the two fundamental pieces of the authorisation - JWT token parsing, and permissions checking. Refer to the readme's for the  [JWT parser](jwt/README.md) and [permissions checker](permissions/README.md) for more information on creating and using them.

It should also be considered how a feature flag may be applied in this case. The authorisation config type contains an `Enabled` boolean for this purpose, but usage of the flag will need to be implemented. 

The JWT token parsing could potentially be done within middleware, and the EntityData that comes from the JWT could be stored in the request content for later use within the handler. Other than that the JWT parser could be used directly within the handler.

Once the JWT token is parsed into EntityData, it can be passed to the permissions checker to determine if the user has access. It's likely at this point that additional data will be needed by the permissions checker to make a decision. This is where the `attributes` parameter of the permissions checker is used - for example to set a collection ID:

```go
  permission := "legacy.read"
  attributes := map[string]string{"collection_id": "collection123"}

  hasPermission, err := permissionChecker.HasPermission(ctx, entityData, permission, attributes)

```

Mock types for the `JWTParser` and `PermissionsChecker` interfaces are available under the `github.com/ONSdigital/dp-authorisation/v2/authorisation/mock` import path.

#### Component testing with authorisation

The `authorisationtest` package provides test JWT tokens, and a fake permissions API that can be used in component tests. 

##### Using the fake permissions API

Instantiate the fake permissions API in the test component, then read the URL value to set the permissions API URL in the config:
```go
fakePermissionsAPI := authorisationtest.NewFakePermissionsAPI()
	c.Config.AuthorisationConfig.PermissionsAPIURL = fakePermissionsAPI.URL()
```
Once the config value is set for the permissions API, use the authorisation code (middleware or permissions checker) as it is used in the service.

##### JWT tokens for component tests

The JWT tokens provided emulate users who are member of different groups. They have been generated to work with the public key that's provided in the default configuration.

To use the test JWT tokens within a component test, register a step that adds the token as a header (example taken from the Identity API):

```go

import (
    "github.com/ONSdigital/dp-authorisation/v2/authorisationtest"
)

...

ctx.Step(`^I am an admin user$`, c.adminJWTToken)

...

func (c *IdentityComponent) adminJWTToken() error {
  err := c.apiFeature.ISetTheHeaderTo(api.AccessTokenHeaderName, authorisationtest.AdminJWTToken)
  return err
}
```
Then the JWT token can be added to a request in the feature file:
```
  Given I am an admin user
  When ...
```

      

