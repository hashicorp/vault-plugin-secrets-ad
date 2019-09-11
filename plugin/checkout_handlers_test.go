package plugin

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func Test_StorageHandler(t *testing.T) {
	// Construct everything we'll need for our tests.
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	serviceAccountName := "becca@example.com"
	testTime := time.Now().UTC()
	testCheckOut := &CheckOut{
		BorrowerEntityID:    "entity-id",
		BorrowerClientToken: "client-token",
		LendingPeriod:       10,
		Due:                 testTime,
	}
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
