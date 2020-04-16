package main

import (
	"fmt"
	"net/http"

	"github.com/ONSdigital/dp-authorisation/auth"
	"github.com/gorilla/mux"
)

var (
	read = auth.Permissions{Read: true}
)

func main() {
	// Set the auth package log namespace.
	auth.LoggerNamespace("<application-name>-auth")

	// GetPermissionsRequestBuilder for authorising access to datasets.
	datasetPermissionsRequestBuilder := auth.NewDatasetPermissionsRequestBuilder("http://localhost:8082", "dataset_id", mux.Vars)

	datasetsPermissions := auth.NewHandler(
		datasetPermissionsRequestBuilder,
		auth.DefaultPermissionsClient(),
		auth.DefaultPermissionsVerifier(),
	)

	// GetPermissionsRequestBuilder for authorising general CMD access (cases where we don't have a collection ID & dataset ID).
	permissionsRequestBuilder := auth.NewPermissionsRequestBuilder("http://localhost:8082")

	permissions := auth.NewHandler(
		permissionsRequestBuilder,
		auth.DefaultPermissionsClient(),
		auth.DefaultPermissionsVerifier(),
	)

	router := mux.NewRouter()
	router.HandleFunc("/datasets", permissions.Require(read, getDatasetsHandlerFunc)).Methods("GET")
	router.HandleFunc("/datasets/{dataset_id}", datasetsPermissions.Require(read, getDatasetHandlerFunc)).Methods("GET")

	fmt.Println("starting server")
	err := http.ListenAndServe(":22000", router)
	if err != nil {
		panic(err)
	}
}

// an example http.HandlerFunc for getting a dataset
func getDatasetsHandlerFunc(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("datasets info here"))
}

// an example http.HandlerFunc for getting a dataset
func getDatasetHandlerFunc(w http.ResponseWriter, r *http.Request) {
	datasetID := mux.Vars(r)["dataset_id"]
	fmt.Printf("dataset %s: info here", datasetID)
	w.Write([]byte("dataset info here"))
}
