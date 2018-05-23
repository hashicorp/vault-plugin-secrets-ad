package client

import (
	"testing"
)

func TestFieldRegistryListsFields(t *testing.T) {
	fields := FieldRegistry.List()
	if len(fields) != 40 {
		t.FailNow()
	}
}

func TestFieldRegistryEqualityComparisonsWork(t *testing.T) {
	fields := FieldRegistry.List()

	foundGivenName := false
	foundSurname := false
	for _, field := range fields {
		if field == FieldRegistry.GivenName {
			foundGivenName = true
		}
		if field == FieldRegistry.Surname {
			foundSurname = true
		}
	}

	if !foundGivenName || !foundSurname {
		t.Fatal("the field registry's equality comparisons are not working")
	}
}

func TestFieldRegistryParsesFieldsByString(t *testing.T) {
	field := FieldRegistry.Parse("sn")
	if field == nil {
		t.Fatal("field not found")
	}
	if field != FieldRegistry.Surname {
		t.Fatal("the field registry is unable to parse registry fields from their string representations")
	}
}
