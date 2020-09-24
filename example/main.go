package main

import (
	"context"
	"net/http"

	"github.com/ONSdigital/dp-authorisation/auth"
	"github.com/ONSdigital/log.go/log"
	"github.com/gorilla/mux"
)

var (
	read = auth.Permissions{Read: true}
)

func main() {
	// Set the log namespace.
	log.Namespace = "example-api"

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

	log.Event(context.Background(), "starting dp-authorisation example API", log.INFO)
	err := http.ListenAndServe(":22000", router)
	if err != nil {
		panic(err)
	}
}

// an example http.HandlerFunc for getting a dataset
func getDatasetsHandlerFunc(w http.ResponseWriter, r *http.Request) {
	log.Event(r.Context(), "get datasets stub invoked", log.INFO)
	w.Write([]byte("datasets info here"))
}

// an example http.HandlerFunc for getting a dataset
func getDatasetHandlerFunc(w http.ResponseWriter, r *http.Request) {
	datasetID := mux.Vars(r)["dataset_id"]
	log.Event(r.Context(), "get dataset stub invoked", log.INFO, log.Data{"dataset_id": datasetID})
	w.Write([]byte("dataset info here"))
}
