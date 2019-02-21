package datastore

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if testDatabaseURL, got := os.LookupEnv("TEST_DATABASE_URL"); got {
		Initialize(testDatabaseURL)
	} else {
		panic("TEST_DATABASE_URL not set")
	}

	err := Migrate()
	if err != nil {
		panic(fmt.Errorf("failed to migrate test database: %v", err))
	}

	code := m.Run()

	err = DropAllTheTables()
	if err != nil {
		panic(fmt.Errorf("failed to empty test database: %v", err))
	}

	os.Exit(code)
}
