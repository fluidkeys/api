package server

import (
	"net/http"
)

func sendSecretHandler(w http.ResponseWriter, r *http.Request) {
}

func receiveSecretsHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello"))
}

func deleteSecretHandler(w http.ResponseWriter, r *http.Request) {
}
