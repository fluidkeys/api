package main

import (
	"fmt"
	"log"
	"os"

	"github.com/fluidkeys/api/cmd"
	"github.com/fluidkeys/api/datastore"
	"github.com/fluidkeys/api/server"
)

func main() {
	err := datastore.Initialize(datastore.MustReadDatabaseURL())
	if err != nil {
		log.Printf("error from ListenAndServe: %v", err)
		panic(err)
	}

	if len(os.Args) == 1 {
		os.Exit(server.Serve())

	} else if os.Args[1] == "migrate" {
		os.Exit(cmd.Migrate())

	} else if os.Args[1] == "print_expired_keys" {
		os.Exit(cmd.PrintExpiredKeys())

	} else if os.Args[1] == "delete_expired_keys" {
		os.Exit(cmd.DeleteExpiredKeys())

	} else if os.Args[1] == "send_emails" {
		os.Exit(cmd.SendEmails())

	} else if os.Args[1] == "send_test_emails" {
		os.Exit(cmd.SendTestEmails())

	} else if os.Args[1] == "migrate_team_rosters" {
		os.Exit(datastore.MigrateTeamRosters())

	} else {
		fmt.Printf("unrecognised command: `%s`\n", os.Args[1])
		os.Exit(1)
	}
}
