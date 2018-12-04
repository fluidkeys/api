package server

import (
	"fmt"
	"net/http"

	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/api/v1structs"
	"github.com/gorilla/mux"
)

func getPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	email := mux.Vars(r)["email"]

	responseData := v1structs.GetPublicKeyResponse{}

	armoredPublicKey, found, err := datastore.GetArmoredPublicKeyForEmail(email)
	if err != nil {
		writeJsonError(w, err, http.StatusInternalServerError)
		return
	} else if !found {
		writeJsonError(
			w,
			fmt.Errorf("couldn't find a public key for email address '%s'", email),
			http.StatusNotFound,
		)
		return
	}

	responseData.ArmoredPublicKey = armoredPublicKey
	writeJsonResponse(w, responseData)
}
