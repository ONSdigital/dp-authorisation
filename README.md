# dp-permissions
Library providing functionality for wrapping API endpoints in a permissions check.

### Configure
Create new `authenticator` providing:
 - The permissions API host. 
 - A `permissions.HTTPClienter` implementation.

```go
rc := rchttp.NewClient()
authenticator := permissions.New("http://localhost:8082", rc)
```

Configure the `auth` package specifying:
 - The dataset ID URI placeholder name
 - A function for retrieving URI parameters
 - An `authenticator`

```go
rc := rchttp.NewClient()
authenticator := permissions.New("http://localhost:8082", rc)
auth.Configure("dataset_id", mux.Vars, authenticator)
```

### Defining required permissions

```go
adminPerm := permissions.CRUD{
    Create: true,
    Read:   true,
    Update: true,
    Delete: true,
}
````

### Applying permissions to an API route

```go
adminPerms := permissions.CRUD{
    Create: true,
    Read:   true,
    Update: true,
    Delete: true,
}

r := mux.NewRouter()
r.HandleFunc("/datasets/{dataset_id}", auth.Require(adminPerms,  func(w http.ResponseWriter, r *http.Request) { ... }))
```