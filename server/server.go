package server

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/fluidkeys/api/datastore"
	"github.com/gorilla/mux"
)

var subrouter *mux.Router

func init() {
	r := mux.NewRouter()
	subrouter = r.PathPrefix("/v1").Subrouter()

	subrouter.HandleFunc("/ping/{word}", pingHandler).Methods("GET")

	subrouter.HandleFunc("/email/verify/{uuid:"+uuid4Pattern+"}", verifyEmailHandler).Methods("GET", "POST")

	subrouter.HandleFunc("/email/{email}/key", getPublicKeyHandler).Methods("GET")
	subrouter.HandleFunc("/email/{email}/key.asc", getAsciiArmoredPublicKeyHandler).Methods("GET")
	subrouter.HandleFunc("/keys", upsertPublicKeyHandler).Methods("POST")

	subrouter.HandleFunc("/secrets", sendSecretHandler).Methods("POST")
	subrouter.HandleFunc("/secrets", listSecretsHandler).Methods("GET")
	subrouter.HandleFunc("/secrets/{uuid:"+uuid4Pattern+"}", deleteSecretHandler).Methods("DELETE")
}

func Serve() error {
	err := datastore.Initialize(datastore.MustReadDatabaseUrl())
	if err != nil {
		panic(err)
	}

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

func pingHandler(w http.ResponseWriter, r *http.Request) {
	err := datastore.Ping()
	if err != nil {
		log.Print(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	pingWord := mux.Vars(r)["word"]

	w.Write([]byte(pingWord))
}

const uuid4Pattern string = `[0-9a-f]{8}\-[0-9a-f]{4}\-4[0-9a-f]{3}\-[89ab][0-9a-f]{3}\-[0-9a-f]{12}`
