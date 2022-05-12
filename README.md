# dp-authorisation

Note: Documetation for v2 of this authorisation library is available  [here](/v2/README.md)
Library providing functionality for applying an authorisation check to `http.HandlerFunc`. 

This will check the incoming request is authenticated (has a valid authorisation token) and then once identified will check if the user or service is authorised to access the endpoint/resources by verifying the user or service has the same permissions as those set against the handler.

### Example Application
See the [example app](/example/main.go), for details of implementing how to use the library.

To run the example application use the following command:

`make debug-example`

The example application will attempt to run on http://localhost:22000 and will attempt to connect to authenticating service via http://localhost:8082.

Use the following curl commands to send requests to example application to test responses.

```
# Without a header setting a service or user auth token, responds with 400 bad request
curl -X GET localhost:22000/datasets

# Wtih an invalid auth token, responds with 401 unauthorised request
curl -X GET localhost:22000/datasets -H "Authorization: <invalid token>"

# With a valid auth token, responds with 200 OK request
curl -X GET localhost:22000/datasets -H "Authorization: <valid token>"
```
