package server

import (
	"encoding/json"
	"github.com/fluidkeys/api/v1structs"
	"log"
	"net/http"
)

func writeJsonResponse(w http.ResponseWriter, responseData interface{}) {
	out, err := json.MarshalIndent(responseData, "", "    ")

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("content-type", "application/json")
	w.Write(out)
}

func writeJsonError(w http.ResponseWriter, err error, statusCode int) {
	log.Print(err)
	responseData := v1structs.ErrorResponse{Detail: err.Error()}

	out, err := json.MarshalIndent(responseData, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(out)
}
