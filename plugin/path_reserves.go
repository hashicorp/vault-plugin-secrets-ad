package plugin

import "time"

const reserveStoragePrefix = "reserve/"

type libraryReserve struct {
	ServiceAccountNames []string      `json:"service_account_names"`
	LendingPeriod       time.Duration `json:"lending_period"`
}

// TODO this is where the following endpoint groups will live:
//  - /<mount>/library
//  - /<mount>/library/:name
