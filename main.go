package main

import (
	"github.com/fluidkeys/api/server"
)

func main() {
	err := server.Serve()
	if err != nil {
		panic(err)
	}
}
