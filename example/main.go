package main

import (
	"net/http"

	"github.com/ONSdigital/dp-authorisation/auth"
	"github.com/ONSdigital/go-ns/rchttp"
	"github.com/ONSdigital/log.go/log"
	"github.com/gorilla/mux"
)

func main() {
	parameterFactory := &auth.DatasetParameterFactory{}
	permissionsVerifier := &auth.PermissionsVerifier{}
	permissionsClient := auth.NewPermissionsClient("http://localhost:8082", &rchttp.Client{})

	auth.Configure("dataset_id",mux.Vars, "test")

	authHandler := auth.NewHandler(parameterFactory, permissionsClient, permissionsVerifier)

	readPermission := auth.Permissions{Read: true}

	router := mux.NewRouter()
	router.HandleFunc("/datasets/{dataset_id}", authHandler.Require(readPermission, getDataset)).Methods("GET")

	log.Event(nil, "starting server")
	err := http.ListenAndServe(":8088", router)
	if err != nil {
		panic(err)
	}
}

func getDataset(w http.ResponseWriter, r *http.Request) {
	log.Event(nil, "auth successful")
	w.Write([]byte("hello world"))
}