package client

import (
	"testing"
)

func TestParseTime(t *testing.T) {
	// This is a sample time returned from AD.
	pwdLastSet := "131680504285591921"
	lastSet, err := ParseTicks(pwdLastSet)
	if err != nil {
		t.Fatal(err)
	}
	if lastSet.String() != "2018-04-12 23:47:08.5591921 +0000 UTC" {
		t.Fatalf("expected last set of \"2018-04-12 23:47:08.5591921 +0000 UTC\" but received %q", lastSet.String())
	}
}
