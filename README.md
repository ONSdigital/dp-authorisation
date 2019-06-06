# dp-autherisation
Library provides functionality for wrapping a `http.HandlerFunc` in an authorisation check. The auth handler accepts 
an `authorisation.Policy` (a list of `CRUD` permissions) that the caller has to have in order to ve granted access to 
the wrapped http handler.

### Configure
Create new `authoriser` providing:
 - The permissions API host. 
 - A `authorisation.HTTPClienter` implementation.

```go
authoriser := authorisation.NewAuthoriser("http://localhost:8082/permissions", httpClienter)
```

Configure the `authorisation` package specifying:
 - The dataset ID URI placeholder name
 - A function for retrieving URI path parameters
 - An `authoriser`

```go
authorisation.Configure("dataset_id", mux.Vars, authoriser)
```

Define an authorisation policy for 1 or more of your handlers. A policy defines the `CRUD` permissions the caller **must** have to be allowed to perform 
the requested action

```go
policy := authorisation.Policy{
    Create: true,
    Read:   true,
    Update: true,
    Delete: true,
}
````

Apply the authorisation to a `http.HandlerFunc`.
```go
r := mux.NewRouter()
...
policy := authorisation.Policy{Read: true}
r.HandleFunc("/datasets/{dataset_id}",  authorisation.Handler(policy,  func(w http.ResponseWriter, r *http.Request) { ... })
```
Any service or user calling this endpoint **must** have all of the permissions defined in the policy to be able to 
successful reach the wrapped `http.HandlerFunc`. If the policy requirements are not satisfied then the appropriate http 
error status is returned and the caller is denied access to the handler. 

As long as the caller has **at least** the required permissions they will be granted access to the endpoint.

##### Example 1
The permissions policy is `R` and the  caller has permissions `CRUD` they will be granted access.

##### Example 2
The permissions policy is `CRUD` and the  caller has permissions `CRD` they will be denied access.

