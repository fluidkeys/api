package server

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func Serve() error {
	r := mux.NewRouter()
	s := r.PathPrefix("/v1").Subrouter()

	s.HandleFunc("/directory/email/{email}", keySearchHandler).Methods("GET")

	s.HandleFunc("/secrets", sendSecretHandler).Methods("POST")
	s.HandleFunc("/secrets", receiveSecretsHandler).Methods("GET")
	s.HandleFunc("/secrets", deleteSecretHandler).Methods("POST")

	http.Handle("/", s)
	return http.ListenAndServe(getPort(), nil)
}

func getPort() string {
	var port = os.Getenv("PORT")
	// Set a default port if there is nothing in the environment
	if port == "" {
		port = "4747"
		fmt.Println("INFO: No PORT environment variable detected, defaulting to " + port)
	}
	return ":" + port
}
