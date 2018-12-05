package server

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

var subrouter *mux.Router

func init() {
	r := mux.NewRouter()
	subrouter = r.PathPrefix("/v1").Subrouter()

	subrouter.HandleFunc("/email/{email}/key", getPublicKeyHandler).Methods("GET")
	subrouter.HandleFunc("/secrets", sendSecretHandler).Methods("POST")
	subrouter.HandleFunc("/secrets", listSecretsHandler).Methods("GET")
	subrouter.HandleFunc("/secrets/{uuid:"+uuid4Pattern+"}", deleteSecretHandler).Methods("DELETE")
}

func Serve() error {
	http.Handle("/", subrouter)
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

const uuid4Pattern string = `[0-9a-f]{8}\-[0-9a-f]{4}\-4[0-9a-f]{3}\-[89ab][0-9a-f]{3}\-[0-9a-f]{12}`
