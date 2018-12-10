package server

import (
	"encoding/json"
	"fmt"
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

func decodeJsonRequest(r *http.Request, requestData interface{}) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return fmt.Errorf("expecting header Content-Type: application/json")
	}

	if r.Body == nil {
		return fmt.Errorf("empty request body")
	}

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&requestData)
	if err != nil {
		return fmt.Errorf("invalid JSON: %v", err)
	}
	return nil
}
