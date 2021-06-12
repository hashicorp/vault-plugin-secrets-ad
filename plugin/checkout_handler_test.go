package plugin

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func setup() (context.Context, logical.Storage, string, bool, *CheckOut) {
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
	autoDisabled := false
	entry, err := logical.StorageEntryJSON(configStorageKey, config)
	if err != nil {
		panic(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		panic(err)
	}
	return ctx, storage, serviceAccountName, autoDisabled, checkOut
}

func TestCheckOutHandlerStorageLayer(t *testing.T) {
	ctx, storage, serviceAccountName, autoDisabled, testCheckOut := setup()

	storageHandler := &checkOutHandler{
		client: &fakeSecretsClient{},
	}

	// Service accounts must initially be checked in to the library
	if err := storageHandler.CheckIn(ctx, storage, serviceAccountName, autoDisabled); err != nil {
		t.Fatal(err)
	}

	// If we try to check something out for the first time, it should succeed.
	if err := storageHandler.CheckOut(ctx, storage, serviceAccountName, autoDisabled, testCheckOut); err != nil {
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
	if err := storageHandler.CheckOut(ctx, storage, serviceAccountName, autoDisabled, testCheckOut); err == nil {
		t.Fatal("expected err but received none")
	} else if err != errCheckedOut {
		t.Fatalf("expected errCheckedOut, but received %s", err)
	}

	// If we try to check something in, it should succeed.
	if err := storageHandler.CheckIn(ctx, storage, serviceAccountName, autoDisabled); err != nil {
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
	if err := storageHandler.CheckIn(ctx, storage, serviceAccountName, autoDisabled); err != nil {
		t.Fatal(err)
	}

	// If we check it out again, it should succeed.
	if err := storageHandler.CheckOut(ctx, storage, serviceAccountName, autoDisabled, testCheckOut); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordHandlerInterfaceFulfillment(t *testing.T) {
	ctx, storage, serviceAccountName, autoDisabled, checkOut := setup()

	passwordHandler := &checkOutHandler{
		client: &fakeSecretsClient{},
	}

	// We must always start managing a service account by checking it in.
	if err := passwordHandler.CheckIn(ctx, storage, serviceAccountName, autoDisabled); err != nil {
		t.Fatal(err)
	}

	// There should be no error during check-out.
	if err := passwordHandler.CheckOut(ctx, storage, serviceAccountName, autoDisabled, checkOut); err != nil {
		t.Fatal(err)
	}

	// The password should get rotated successfully during check-in.
	origPassword, err := retrievePassword(ctx, storage, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if err := passwordHandler.CheckIn(ctx, storage, serviceAccountName, autoDisabled); err != nil {
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

func TestAutoDisabledAccount(t *testing.T) {
	ctx, storage, serviceAccountName, autoDisabled, testCheckOut := setup()
	autoDisabled = true

	fakeClient := &fakeSecretsClient{}

	accountDisabledHandler := &checkOutHandler{
		client: fakeClient,
	}

	// Initial check-in. Account should be disabled
	if err := accountDisabledHandler.CheckIn(ctx, storage, serviceAccountName, autoDisabled); err != nil {
		t.Fatal(err)
	}
	if fakeClient.disableAccountCalls != 1 {
		t.Errorf("Disabled account has not been called (%d)", fakeClient.disableAccountCalls)
	}

	// Check the account out. Account should be enabled
	if err := accountDisabledHandler.CheckOut(ctx, storage, serviceAccountName, autoDisabled, testCheckOut); err != nil {
		t.Fatal(err)
	}
	if fakeClient.enableAccountCalls != 1 {
		t.Error("Enable account has not been called")
	}
	// Then Checkin again
	if err := accountDisabledHandler.CheckIn(ctx, storage, serviceAccountName, autoDisabled); err != nil {
		t.Fatal(err)
	}
	if fakeClient.disableAccountCalls != 2 {
		t.Error("Disabled account has not been called for the second times")
	}
	autoDisabled = false
	// Then CheckOut  again, but inactivate autoDisabled feature
	if err := accountDisabledHandler.CheckOut(ctx, storage, serviceAccountName, autoDisabled, testCheckOut); err != nil {
		t.Fatal(err)
	}
	if fakeClient.enableAccountCalls != 1 {
		t.Error("Enable account should not be called")
	}

	// Then Check in again, but inactivate autoDisabled feature
	if err := accountDisabledHandler.CheckIn(ctx, storage, serviceAccountName, autoDisabled); err != nil {
		t.Fatal(err)
	}
	if fakeClient.disableAccountCalls != 2 {
		t.Error("Disabled account has not been called for the second times")
	}
}
