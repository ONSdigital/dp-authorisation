# dp-autherisation
Library providing functionality for applying an authorisation check to `http.HandlerFunc`.

## Example
```
package main

import (
	"net/http"

	"github.com/ONSdigital/dp-authorisation/auth"
	"github.com/ONSdigital/go-ns/rchttp"
	"github.com/ONSdigital/log.go/log"
	"github.com/gorilla/mux"
)

func main() {
	// Set the auth package log namespace.
	auth.Configure("some-name-here")

	// create permissions verifier - PermissionsVerifier is the default implementation.
	permissionsVerifier := &auth.PermissionsVerifier{}

	// create a permissions client
	permissionsClient := auth.NewPermissionsClient("http://localhost:8082", &rchttp.Client{})


	// DatasetParameterFactory is an implementation of ParameterFactory and encapsulate the logic for:
	// 	- Extracting the required headers and parameters from inbound requests
	//	- Creating an outbound get dataset permissions request to the dataset API.
	datasetParamFactory := &auth.DatasetParameterFactory{
		GetRequestVarsFunc: mux.Vars,
		DatasetIDKey:       "dataset_id",
	}

	// create a new auth handler for checking dataset permissions.
	datasetsAuth := auth.NewHandler(datasetParamFactory, permissionsClient, permissionsVerifier)


	// InstanceParameterFactory is an implementation of ParameterFactory and knows how to check instance permissions.
	instanceParamFactory := &auth.InstanceParameterFactory{}

	// create a new auth handler for checking instance permissions.
	instancesAuth := auth.NewHandler(instanceParamFactory, permissionsClient, permissionsVerifier)

	router := mux.NewRouter()

	// permission definitions
	read := auth.Permissions{Read: true}
	update := auth.Permissions{Update: true}

	// getDatasetHandlerFunc requires the caller to have datasets READ permissions.
	router.HandleFunc("/datasets/{dataset_id}", datasetsAuth.Require(read, getDatasetHandlerFunc)).Methods("GET")

	// putInstanceHandlerFunc requires the caller to have instance UPDATE permissions.
	router.HandleFunc("/instances/{instance_id}", instancesAuth.Require(update, putInstanceHandlerFunc)).Methods("PUT")

	log.Event(nil, "starting server")
	err := http.ListenAndServe(":8088", router)
	if err != nil {
		panic(err)
	}
}

// an example http.HandlerFunc for getting a dataset
func getDatasetHandlerFunc(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("dataset info here"))
}

func putInstanceHandlerFunc(w http.ResponseWriter, r *http.Request) {
	log.Event(nil, "auth successful")
	w.Write([]byte("hello world"))
}
```