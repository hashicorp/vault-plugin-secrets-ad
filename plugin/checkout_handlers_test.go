package plugin

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func setup() (context.Context, logical.Storage, string, *CheckOut) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	serviceAccountName := "becca@example.com"
	checkOut := &CheckOut{
		BorrowerEntityID:    "entity-id",
		BorrowerClientToken: "client-token",
		LendingPeriod:       10,
		Due:                 time.Now().UTC(),
	}
	config := &configuration{
		PasswordConf: &passwordConf{
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

func Test_StorageHandler(t *testing.T) {
	ctx, storage, serviceAccountName, testCheckOut := setup()

	storageHandler := &StorageHandler{}

	// If we try to check something out for the first time, it should succeed.
	if err := storageHandler.CheckOut(ctx, storage, serviceAccountName, testCheckOut); err != nil {
		t.Fatal(err)
	}

	// We should have the testCheckOut in storage now.
	storedCheckOut, err := storageHandler.Status(ctx, storage, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if storedCheckOut == nil {
		t.Fatal("storedCheckOut should not be nil")
	}
	if !reflect.DeepEqual(testCheckOut, storedCheckOut) {
		t.Fatalf(fmt.Sprintf(`expected %s to be equal to %s`, testCheckOut, storedCheckOut))
	}

	// If we try to check something out that's already checked out, we should
	// get a CurrentlyCheckedOutErr.
	if err := storageHandler.CheckOut(ctx, storage, serviceAccountName, testCheckOut); err == nil {
		t.Fatal("expected err but received none")
	} else if err != CurrentlyCheckedOut {
		t.Fatalf("expected CurrentlyCheckedOut, but received %s", err)
	}

	// If we try to check something in, it should succeed.
	if err := storageHandler.CheckIn(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}

	// We should no longer have the testCheckOut in storage.
	storedCheckOut, err = storageHandler.Status(ctx, storage, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if storedCheckOut != nil {
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

	// If we try to delete something, it should succeed.
	if err := storageHandler.Delete(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}

	// We should again no longer have the testCheckOut in storage.
	storedCheckOut, err = storageHandler.Status(ctx, storage, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if storedCheckOut != nil {
		t.Fatal("storedCheckOut should be nil")
	}

	// If we try to delete it again, it should have the same behavior.
	if err := storageHandler.Delete(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordHandlerInterfaceFulfillment(t *testing.T) {
	ctx, storage, serviceAccountName, checkOut := setup()

	passwordHandler := &PasswordHandler{
		client: &fakeSecretsClient{},
		child:  &fakeCheckOutHandler{},
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
	if origPassword != "" {
		t.Fatal("expected empty password")
	}
	if err := passwordHandler.CheckIn(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}
	currPassword, err := retrievePassword(ctx, storage, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if currPassword == origPassword {
		t.Fatal("expected new password, but received none")
	}

	// There should be no error during delete and the password should be deleted.
	if err := passwordHandler.Delete(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}

	// There should be no error during status.
	currPassword, err = retrievePassword(ctx, storage, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if currPassword != "" {
		t.Fatal("expected empty password")
	}
	checkOut, err = passwordHandler.Status(ctx, storage, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if checkOut != nil {
		t.Fatal("expected checkOut to be nil")
	}
}

func TestPasswordHandlerWALHandling(t *testing.T) {
	ctx, storage, _, _ := setup()

	// First, try to do a bunch of password updates but throw an error whenever we try to reach AD.
	testServiceAccountNames := []string{
		"a@example.com",
		"b@example.com",
		"c@example.com",
	}
	passwordHandler := &PasswordHandler{
		client: &fakeSecretsClient{throwErrs: true},
		child:  &fakeCheckOutHandler{},
	}

	for _, serviceAccountName := range testServiceAccountNames {
		if err := passwordHandler.CheckIn(ctx, storage, serviceAccountName); err == nil {
			t.Fatal("expected err")
		}
	}

	// We should now have 3 WAL entries.
	walIDs, err := framework.ListWAL(ctx, storage)
	if err != nil {
		t.Fatal(err)
	}
	if len(walIDs) != len(testServiceAccountNames) {
		t.Fatal("expected there to be one WAL for each service account whose password we couldn't update")
	}

	// Now retry them with a non-error-throwing secrets client to simulate that transient errs
	// have ceased.
	retryFunc := retryFailedPasswordUpdates(hclog.NewNullLogger(), &fakeSecretsClient{})
	if err := retryFunc(ctx, &logical.Request{Storage: storage}); err != nil {
		t.Fatal(err)
	}

	// We should now have 0 WAL entries.
	walIDs, err = framework.ListWAL(ctx, storage)
	if err != nil {
		t.Fatal(err)
	}
	if len(walIDs) != 0 {
		t.Fatal("expected there to be no further WALs")
	}

	// We should have no errors when the retry func runs without anything to do.
	if err := retryFunc(ctx, &logical.Request{Storage: storage}); err != nil {
		t.Fatal(err)
	}
}

type fakeCheckOutHandler struct{}

func (f *fakeCheckOutHandler) CheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
	return nil
}

func (f *fakeCheckOutHandler) CheckIn(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	return nil
}

func (f *fakeCheckOutHandler) Delete(ctx context.Context, storage logical.Storage, serviceAccountName string) error {
	return nil
}

func (f *fakeCheckOutHandler) Status(ctx context.Context, storage logical.Storage, serviceAccountName string) (*CheckOut, error) {
	return nil, nil
}
