package plugin

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func setup() (context.Context, logical.Storage, string, *CheckOut) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	serviceAccountName := "becca@example.com"
	checkOut := &CheckOut{
		BorrowerEntityID:    "entity-id",
		BorrowerClientToken: "client-token",
	}
	config := &configuration{
		PasswordConf: passwordConf{
			Length: 14,
		},
	}
	entry, err := logical.StorageEntryJSON(configStorageKey, config)
	if err != nil {
		panic(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		panic(err)
	}
	return ctx, storage, serviceAccountName, checkOut
}

func TestCheckOutHandlerStorageLayer(t *testing.T) {
	ctx, storage, serviceAccountName, testCheckOut := setup()

	storageHandler := &checkOutHandler{
		client: &fakeSecretsClient{},
	}

	// Service accounts must initially be checked in to the library
	if err := storageHandler.CheckIn(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}

	// If we try to check something out for the first time, it should succeed.
	if err := storageHandler.CheckOut(ctx, storage, serviceAccountName, testCheckOut); err != nil {
		t.Fatal(err)
	}

	// We should have the testCheckOut in storage now.
	storedCheckOut, err := storageHandler.LoadCheckOut(ctx, storage, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if storedCheckOut == nil {
		t.Fatal("storedCheckOut should not be nil")
	}
	if !reflect.DeepEqual(testCheckOut, storedCheckOut) {
		t.Fatalf(fmt.Sprintf(`expected %+v to be equal to %+v`, testCheckOut, storedCheckOut))
	}

	// If we try to check something out that's already checked out, we should
	// get a CurrentlyCheckedOutErr.
	if err := storageHandler.CheckOut(ctx, storage, serviceAccountName, testCheckOut); err == nil {
		t.Fatal("expected err but received none")
	} else if err != errCheckedOut {
		t.Fatalf("expected errCheckedOut, but received %s", err)
	}

	// If we try to check something in, it should succeed.
	if err := storageHandler.CheckIn(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}

	// We should no longer have the testCheckOut in storage.
	storedCheckOut, err = storageHandler.LoadCheckOut(ctx, storage, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if !storedCheckOut.IsAvailable {
		t.Fatal("storedCheckOut should be nil")
	}

	// If we try to check it in again, it should have the same behavior.
	if err := storageHandler.CheckIn(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}

	// If we check it out again, it should succeed.
	if err := storageHandler.CheckOut(ctx, storage, serviceAccountName, testCheckOut); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordHandlerInterfaceFulfillment(t *testing.T) {
	ctx, storage, serviceAccountName, checkOut := setup()

	passwordHandler := &checkOutHandler{
		client: &fakeSecretsClient{},
	}

	// We must always start managing a service account by checking it in.
	if err := passwordHandler.CheckIn(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}

	// There should be no error during check-out.
	if err := passwordHandler.CheckOut(ctx, storage, serviceAccountName, checkOut); err != nil {
		t.Fatal(err)
	}

	// The password should get rotated successfully during check-in.
	origPassword, err := retrievePassword(ctx, storage, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if err := passwordHandler.CheckIn(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}
	currPassword, err := retrievePassword(ctx, storage, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if currPassword == "" || currPassword == origPassword {
		t.Fatal("expected password, but received none")
	}

	// There should be no error during delete and the password should be deleted.
	if err := passwordHandler.Delete(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}

	currPassword, err = retrievePassword(ctx, storage, serviceAccountName)
	if err != errNotFound {
		t.Fatal("expected errNotFound")
	}

	checkOut, err = passwordHandler.LoadCheckOut(ctx, storage, serviceAccountName)
	if err != errNotFound {
		t.Fatal("expected err not found")
	}
	if checkOut != nil {
		t.Fatal("expected checkOut to be nil")
	}
}
