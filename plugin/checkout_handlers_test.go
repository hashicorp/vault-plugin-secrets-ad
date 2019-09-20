package plugin

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
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
		Due:                 time.Now().Add(time.Second * 10).Round(time.Nanosecond),
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
	if testCheckOut.BorrowerEntityID != storedCheckOut.BorrowerEntityID {
		t.Fatalf(fmt.Sprintf(`expected %s to be equal to %s`, testCheckOut, storedCheckOut))
	}
	if testCheckOut.BorrowerClientToken != storedCheckOut.BorrowerClientToken {
		t.Fatalf(fmt.Sprintf(`expected %s to be equal to %s`, testCheckOut, storedCheckOut))
	}
	if testCheckOut.LendingPeriod != storedCheckOut.LendingPeriod {
		t.Fatalf(fmt.Sprintf(`expected %s to be equal to %s`, testCheckOut, storedCheckOut))
	}
	if testCheckOut.Due.String() != storedCheckOut.Due.String() {
		t.Fatalf(fmt.Sprintf(`expected %s to be equal to %s`, testCheckOut, storedCheckOut))
	}

	// If we try to check something out that's already checked out, we should
	// get a CurrentlyCheckedOutErr.
	if err := storageHandler.CheckOut(ctx, storage, serviceAccountName, testCheckOut); err == nil {
		t.Fatal("expected err but received none")
	} else if err != ErrCurrentlyCheckedOut {
		t.Fatalf("expected ErrCurrentlyCheckedOut, but received %s", err)
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
}

func TestValidateInputs(t *testing.T) {
	ctx, storage, serviceAccountName, checkOut := setup()

	// Failure cases.
	v := &InputValidator{}
	if err := v.validateInputs(nil, storage, serviceAccountName, checkOut, true); err == nil {
		t.Fatal("expected err because ctx isn't provided")
	}
	if err := v.validateInputs(ctx, nil, serviceAccountName, checkOut, true); err == nil {
		t.Fatal("expected err because storage isn't provided")
	}
	if err := v.validateInputs(ctx, storage, "", checkOut, true); err == nil {
		t.Fatal("expected err because serviceAccountName isn't provided")
	}
	if err := v.validateInputs(ctx, storage, serviceAccountName, nil, true); err == nil {
		t.Fatal("expected err because checkOut isn't provided")
	}
	// Success cases.
	if err := v.validateInputs(ctx, storage, serviceAccountName, checkOut, true); err != nil {
		t.Fatal(err)
	}
	if err := v.validateInputs(ctx, storage, serviceAccountName, nil, false); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordHandlerInterfaceFulfillment(t *testing.T) {
	ctx, storage, serviceAccountName, checkOut := setup()

	passwordHandler := &PasswordHandler{
		client:          &fakeSecretsClient{},
		CheckOutHandler: &fakeCheckOutHandler{},
	}

	// There should be no error during check-out.
	if err := passwordHandler.CheckOut(ctx, storage, serviceAccountName, checkOut); err != nil {
		t.Fatal(err)
	}

	// The password should get rotated successfully during check-in.
	_, err := retrievePassword(ctx, storage, serviceAccountName)
	if err != ErrNotFound {
		t.Fatal("expected ErrNotFound")
	}
	if err := passwordHandler.CheckIn(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}
	currPassword, err := retrievePassword(ctx, storage, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if currPassword == "" {
		t.Fatal("expected password, but received none")
	}

	// There should be no error during delete and the password should be deleted.
	if err := passwordHandler.Delete(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}

	currPassword, err = retrievePassword(ctx, storage, serviceAccountName)
	if err != ErrNotFound {
		t.Fatal("expected ErrNotFound")
	}
	checkOut, err = passwordHandler.Status(ctx, storage, serviceAccountName)
	if err != nil {
		t.Fatal(err)
	}
	if checkOut != nil {
		t.Fatal("expected checkOut to be nil")
	}
}

func TestServiceAccountLocker(t *testing.T) {
	// Check that all the main methods work.
	ctx, storage, serviceAccountName, checkOut := setup()

	serviceAccountLocker := NewServiceAccountLocker(&fakeCheckOutHandler{})
	if err := serviceAccountLocker.CheckOut(ctx, storage, serviceAccountName, checkOut); err != nil {
		t.Fatal(err)
	}
	if err := serviceAccountLocker.CheckIn(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}
	if _, err := serviceAccountLocker.Status(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}
	if err := serviceAccountLocker.Delete(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}
}

// TestCheckOutHandlerRace is intended to be run with the -race flag
func TestCheckOutHandlerRace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping due to short test run")
	}

	ctx, storage, serviceAccountName, checkOut := setup()

	leaderHandler, err := NewCheckOutHandler(ctx, true, hclog.Default(), storage, &fakeSecretsClient{})
	if err != nil {
		t.Fatal(err)
	}
	followerHandler, err := NewCheckOutHandler(ctx, false, hclog.Default(), storage, &fakeSecretsClient{})
	if err != nil {
		t.Fatal(err)
	}

	rand.Seed(time.Now().UnixNano())
	start := make(chan bool)
	done := make(chan bool)
	numWorkers := 100
	for _, checkOutHandler := range []CheckOutHandler{leaderHandler, followerHandler} {
		for i := 0; i < numWorkers; i++ {
			go func() {
				// Ensure all goroutines start at the same time.
				<-start
				// Each routine will call one function randomly on the same service account,
				// so draw a number from 0 to 3 to pick which one....
				switch rand.Intn(5) {
				case 0:
					if err := checkOutHandler.CheckIn(ctx, storage, serviceAccountName); err != nil {
						t.Fatal(err)
					}
				case 1:
					if err := checkOutHandler.CheckOut(ctx, storage, serviceAccountName, checkOut); err != nil && err != ErrCurrentlyCheckedOut {
						t.Fatal(err)
					}
				case 2:
					if _, err := checkOutHandler.Status(ctx, storage, serviceAccountName); err != nil {
						t.Fatal(err)
					}
				case 3:
					if err := checkOutHandler.Delete(ctx, storage, serviceAccountName); err != nil {
						t.Fatal(err)
					}
				case 4:
					if err := checkOutHandler.RenewCheckOut(ctx, storage, serviceAccountName, checkOut); err != nil && err != ErrNotCurrentlyCheckedOut {
						t.Fatal(err)
					}
				}
				// State you're done.
				done <- true
			}()
		}
	}

	close(start)
	timer := time.NewTimer(time.Second * 10)
	for i := 0; i < numWorkers*2; i++ {
		select {
		case <-done:
			continue
		case <-timer.C:
			t.Fatal("test took more than 10 seconds for all 100 to get through")
		}
	}
}

func TestOverdueWatcher(t *testing.T) {
	ctx, storage, serviceAccountName, checkOut := setup()
	logger := hclog.Default()
	logger.SetLevel(hclog.Debug)
	checkOut.Due = time.Now().Add(time.Hour)

	// Create a realistic OverdueWatcher.
	serviceAccountLocker := NewServiceAccountLocker(&PasswordHandler{
		client:          &fakeSecretsClient{},
		CheckOutHandler: &StorageHandler{},
	})

	overdueWatcher := NewOverdueWatcher(logger, storage, serviceAccountLocker)
	if err := overdueWatcher.CheckOut(ctx, storage, serviceAccountName, checkOut); err != nil {
		t.Fatal(err)
	}
	if _, err := overdueWatcher.Status(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}
	if err := overdueWatcher.CheckIn(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}
	if _, err := overdueWatcher.Status(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}
	if err := overdueWatcher.CheckOut(ctx, storage, serviceAccountName, checkOut); err != nil {
		t.Fatal(err)
	}
	if err := overdueWatcher.CheckIn(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}
	if err := overdueWatcher.Delete(ctx, storage, serviceAccountName); err != nil {
		t.Fatal(err)
	}
	if err := overdueWatcher.CheckOut(ctx, storage, serviceAccountName, checkOut); err != nil {
		t.Fatal(err)
	}
}

func TestOverdueWatcherAutomatesCheckIns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping due to short test run")
	}

	ctx, storage, serviceAccountName, checkOut := setup()

	// Create a realistic OverdueWatcher.
	serviceAccountLocker := NewServiceAccountLocker(&PasswordHandler{
		client:          &fakeSecretsClient{},
		CheckOutHandler: &StorageHandler{},
	})
	logger := hclog.Default()
	logger.SetLevel(hclog.Debug)
	overdueWatcher := NewOverdueWatcher(logger, storage, serviceAccountLocker)

	// First, check out the account with it due in 10 seconds.
	if err := overdueWatcher.CheckOut(ctx, storage, serviceAccountName, checkOut); err != nil {
		t.Fatal(err)
	}
	// Next, if we immediately try to check it out again, we should get that it's currently checked out.
	if err := overdueWatcher.CheckOut(ctx, storage, serviceAccountName, checkOut); err == nil {
		t.Fatal("expected an error because the account should currently be checked out")
	} else if err != ErrCurrentlyCheckedOut {
		t.Fatal(err)
	}
	// Now, if we wait 11 seconds, the lending period should end, the account should get checked back in,
	// and we should be able to check it out again.
	time.Sleep(time.Second * 11)

	checkOut.Due = time.Now().Add(time.Second * 10)
	if err := overdueWatcher.CheckOut(ctx, storage, serviceAccountName, checkOut); err != nil {
		t.Fatal(err)
	}
}

type fakeCheckOutHandler struct{}

func (f *fakeCheckOutHandler) CheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
	return nil
}

func (f *fakeCheckOutHandler) RenewCheckOut(ctx context.Context, storage logical.Storage, serviceAccountName string, checkOut *CheckOut) error {
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
