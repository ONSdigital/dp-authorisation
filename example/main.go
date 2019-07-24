package main

import (
	"net/http"

	"github.com/ONSdigital/dp-authorisation/auth"
	"github.com/ONSdigital/log.go/log"
	"github.com/gorilla/mux"
)

func main() {
	// Set the auth package log namespace.
	auth.LoggerNamespace("some-name-here")

	datasetPermissionsRequestBuilder := &auth.DatasetPermissionsRequestBuilder{
		Host:               "http://localhost:8082",
		DatasetIDKey:       "dataset_id",
		GetRequestVarsFunc: mux.Vars,
	}

	// create a new auth handler for checking dataset permissions.
	datasetsAuth := auth.NewHandler(
		datasetPermissionsRequestBuilder,
		auth.DefaultPermissionsClient(),
		auth.DefaultPermissionsVerifier(),
	)

	router := mux.NewRouter()

	// permission definitions
	read := auth.Permissions{Read: true}

	// getDatasetHandlerFunc requires the caller to have datasets READ permissions.
	router.HandleFunc("/datasets/{dataset_id}", datasetsAuth.Require(read, getDatasetHandlerFunc)).Methods("GET")

	log.Event(nil, "starting server")
	err := http.ListenAndServe(":22000", router)
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
