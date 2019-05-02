package server

import (
	"log"
	"net/http"

	"github.com/fluidkeys/api/v1structs"
)

func createEventHandler(w http.ResponseWriter, r *http.Request) {
	requestData := v1structs.CreateEventRequest{}
	if err := decodeJsonRequest(r, &requestData); err != nil {
		writeJsonError(w, err, http.StatusBadRequest)
		return
	}

	log.Printf("event: %#v", requestData)
	w.WriteHeader(http.StatusOK)
	w.Write(nil)
}
