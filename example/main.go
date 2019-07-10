package main

import (
	"net/http"

	"github.com/ONSdigital/dp-authorisation/auth"
	"github.com/ONSdigital/go-ns/rchttp"
	"github.com/ONSdigital/log.go/log"
	"github.com/gorilla/mux"
)

func main() {
	permissionsClient := auth.NewPermissionsClient("http://localhost:8082", &rchttp.Client{})
	auth.DefaultConfiguration("dataset_id", permissionsClient)

	requireAuth := auth.RequireDatasetPermissions

	readPermission := auth.Permissions{Read: true}

	router := mux.NewRouter()
	router.HandleFunc("/datasets/{dataset_id}", requireAuth(readPermission, getDataset)).Methods("GET")

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