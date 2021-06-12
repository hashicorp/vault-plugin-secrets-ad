package plugin

import (
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// The AD library of service accounts that can be checked out
// is a discrete set of features. This test suite provides
// end-to-end tests of these interrelated endpoints.
func TestCheckOuts(t *testing.T) {
	// Plant a config.
	t.Run("plant config", PlantConfig)

	// Exercise all set endpoints.
	t.Run("write set", WriteSet)
	t.Run("read set", ReadSet)
	t.Run("read set status", ReadSetStatus)
	t.Run("write set toggle off", WriteSetToggleOff)
	t.Run("read set toggle off", ReadSetToggleOff)
	t.Run("write set auto disable account off", WriteSetAutoDisableAccountOff)
	t.Run("read set auto disable account off", ReadSetAutoDisableAccountOff)
	t.Run("write conflicting set", WriteSetWithConflictingServiceAccounts)
	t.Run("list sets", ListSets)
	t.Run("delete set", DeleteSet)

	// Do some common updates on sets and ensure they work.
	t.Run("write set", WriteSet)
	t.Run("add service account", AddAnotherServiceAccount)
	t.Run("remove service account", RemoveServiceAccount)

	t.Run("check initial status", CheckInitialStatus)
	t.Run("check out account", PerformCheckOut)
	t.Run("check updated status", CheckUpdatedStatus)
	t.Run("normal check in", NormalCheckIn)
	t.Run("return to initial status", CheckInitialStatus)
	t.Run("check out again", PerformCheckOut)
	t.Run("check updated status", CheckUpdatedStatus)
	t.Run("force check in", ForceCheckIn)
	t.Run("check all are available", CheckInitialStatus)
}

// TestCheckOutRaces executes a whole bunch of calls at once and only looks for
// races. Responses are ignored because they'll vary depending on execution order.
func TestCheckOutRaces(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping check for races in the checkout system due to short flag")
	}

	// Get 100 goroutines ready to go.
	numParallel := 100
	start := make(chan bool, 1)
	end := make(chan bool, numParallel)
	for i := 0; i < numParallel; i++ {
		go func() {
			<-start
			testBackend.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   testStorage,
				Data: map[string]interface{}{
					"service_account_names":        []string{"tester1@example.com", "tester2@example.com"},
					"ttl":                          "10h",
					"max_ttl":                      "11h",
					"disable_check_in_enforcement": true,
				},
			})
			testBackend.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   testStorage,
				Data: map[string]interface{}{
					"service_account_names": []string{"tester1@example.com", "tester2@example.com", "tester3@example.com"},
				},
			})
			testBackend.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   testStorage,
				Data: map[string]interface{}{
					"service_account_names": []string{"tester1@example.com", "tester2@example.com"},
				},
			})
			testBackend.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   testStorage,
			})
			testBackend.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   testStorage,
				Data: map[string]interface{}{
					"service_account_names":        []string{"tester1@example.com", "tester2@example.com"},
					"ttl":                          "10h",
					"disable_check_in_enforcement": false,
					"auto_disable_account":         true,
				},
			})
			testBackend.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   testStorage,
			})
			testBackend.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set/status",
				Storage:   testStorage,
			})
			testBackend.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation,
				Path:      libraryPrefix + "test-set2",
				Storage:   testStorage,
				Data: map[string]interface{}{
					"service_account_names": "tester1@example.com",
				},
			})
			testBackend.HandleRequest(ctx, &logical.Request{
				Operation: logical.ListOperation,
				Path:      libraryPrefix,
				Storage:   testStorage,
			})
			testBackend.HandleRequest(ctx, &logical.Request{
				Operation: logical.DeleteOperation,
				Path:      libraryPrefix + "test-set",
				Storage:   testStorage,
			})
			testBackend.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set/status",
				Storage:   testStorage,
			})
			testBackend.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set/check-out",
				Storage:   testStorage,
			})
			testBackend.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set/status",
				Storage:   testStorage,
			})
			testBackend.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "test-set/check-in",
				Storage:   testStorage,
			})
			testBackend.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      libraryPrefix + "manage/test-set/check-in",
				Storage:   testStorage,
			})
			end <- true
		}()
	}

	// Start them all at once.
	close(start)

	// Wait for them all to finish.
	timer := time.NewTimer(15 * time.Second)
	for i := 0; i < numParallel; i++ {
		select {
		case <-timer.C:
			t.Fatal("test took more than 15 seconds, may be deadlocked")
		case <-end:
			continue
		}
	}
}

func WriteSet(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      libraryPrefix + "test-set",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"service_account_names":        []string{"tester1@example.com", "tester2@example.com"},
			"ttl":                          "10h",
			"max_ttl":                      "11h",
			"disable_check_in_enforcement": true,
			"auto_disable_account":         true,
		},
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatalf("expected an empty response, got: %v", resp)
	}
}

func AddAnotherServiceAccount(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      libraryPrefix + "test-set",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"service_account_names": []string{"tester1@example.com", "tester2@example.com", "tester3@example.com"},
		},
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatalf("expected an empty response, got: %v", resp)
	}
}

func RemoveServiceAccount(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      libraryPrefix + "test-set",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"service_account_names": []string{"tester1@example.com", "tester2@example.com"},
		},
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatalf("expected an empty response, got: %v", resp)
	}
}

func ReadSet(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      libraryPrefix + "test-set",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	serviceAccountNames := resp.Data["service_account_names"].([]string)
	if len(serviceAccountNames) != 2 {
		t.Fatal("expected 2")
	}
	disableCheckInEnforcement := resp.Data["disable_check_in_enforcement"].(bool)
	if !disableCheckInEnforcement {
		t.Fatal("check-in enforcement should be disabled")
	}
	autoDisableAccount := resp.Data["auto_disable_account"].(bool)
	if !autoDisableAccount {
		t.Fatal("autoDisable should be enabled")
	}
	ttl := resp.Data["ttl"].(int64)
	if ttl != 10*60*60 { // 10 hours
		t.Fatal(ttl)
	}
	maxTTL := resp.Data["max_ttl"].(int64)
	if maxTTL != 11*60*60 { // 11 hours
		t.Fatal(maxTTL)
	}
}

func WriteSetToggleOff(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      libraryPrefix + "test-set",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"service_account_names":        []string{"tester1@example.com", "tester2@example.com"},
			"ttl":                          "10h",
			"disable_check_in_enforcement": false,
		},
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatalf("expected an empty response, got: %v", resp)
	}
}

func ReadSetToggleOff(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      libraryPrefix + "test-set",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	serviceAccountNames := resp.Data["service_account_names"].([]string)
	if len(serviceAccountNames) != 2 {
		t.Fatal("expected 2")
	}
	disableCheckInEnforcement := resp.Data["disable_check_in_enforcement"].(bool)
	if disableCheckInEnforcement {
		t.Fatal("check-in enforcement should be enabled")
	}
}

func WriteSetAutoDisableAccountOff(t *testing.T) {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      libraryPrefix + "test-set",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"service_account_names":        []string{"tester1@example.com", "tester2@example.com"},
			"ttl":                          "10h",
			"disable_check_in_enforcement": false,
			"auto_disable_account":         false,
		},
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatalf("expected an empty response, got: %v", resp)
	}
}

func ReadSetAutoDisableAccountOff(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      libraryPrefix + "test-set",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	serviceAccountNames := resp.Data["service_account_names"].([]string)
	if len(serviceAccountNames) != 2 {
		t.Fatal("expected 2")
	}
	autoDisableAccount := resp.Data["auto_disable_account"].(bool)
	if autoDisableAccount {
		t.Fatal("autoDisable should be disabled")
	}
}

func ReadSetStatus(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      libraryPrefix + "test-set/status",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	if len(resp.Data) != 2 {
		t.Fatal("length should be 2 because there are two service accounts in this set")
	}
	if resp.Data["tester1@example.com"] == nil {
		t.Fatal("expected non-nil map")
	}
	testerStatus := resp.Data["tester1@example.com"].(map[string]interface{})
	if !testerStatus["available"].(bool) {
		t.Fatal("should be available for checkout")
	}
}

func WriteSetWithConflictingServiceAccounts(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      libraryPrefix + "test-set2",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"service_account_names": "tester1@example.com",
		},
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected err response because we're adding a service account managed by another set")
	}
}

func ListSets(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      libraryPrefix,
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Data["keys"] == nil {
		t.Fatal("expected non-nil data")
	}
	listedKeys := resp.Data["keys"].([]string)
	if len(listedKeys) != 1 {
		t.Fatalf("expected 1 key but received %s", listedKeys)
	}
	if "test-set" != listedKeys[0] {
		t.Fatal("expected test-set to be the only listed item")
	}
}

func DeleteSet(t *testing.T) {
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      libraryPrefix + "test-set",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatalf("expected an empty response, got: %v", resp)
	}
}

func CheckInitialStatus(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      libraryPrefix + "test-set/status",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Data["tester1@example.com"] == nil {
		t.Fatal("expected map to not be nil")
	}
	tester1CheckOut := resp.Data["tester1@example.com"].(map[string]interface{})
	available := tester1CheckOut["available"].(bool)
	if !available {
		t.Fatal("tester1 should be available")
	}

	if resp.Data["tester2@example.com"] == nil {
		t.Fatal("expected map to not be nil")
	}
	tester2CheckOut := resp.Data["tester2@example.com"].(map[string]interface{})
	available = tester2CheckOut["available"].(bool)
	if !available {
		t.Fatal("tester2 should be available")
	}
}

func PerformCheckOut(t *testing.T) {
	testSecretClient.Clear()

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      libraryPrefix + "test-set/check-out",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Data == nil {
		t.Fatal("expected resp data to not be nil")
	}

	if resp.Data["service_account_name"] == nil {
		t.Fatal("expected string to be populated")
	}
	if resp.Data["service_account_name"].(string) == "" {
		t.Fatal("service account name should be populated")
	}
	if resp.Data["password"].(string) == "" {
		t.Fatal("password should be populated")
	}
	if !resp.Secret.Renewable {
		t.Fatal("lease should be renewable")
	}
	if resp.Secret.TTL != time.Hour*10 {
		t.Fatal("expected 10h TTL")
	}
	if resp.Secret.MaxTTL != time.Hour*11 {
		t.Fatal("expected 11h TTL")
	}
	if resp.Secret.InternalData["service_account_name"].(string) == "" {
		t.Fatal("internal service account name should not be empty")
	}
	if testSecretClient.enableAccountCalls != 1 {
		t.Fatalf("Enable account method should be called once")
	}
}

func CheckUpdatedStatus(t *testing.T) {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      libraryPrefix + "test-set/status",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	if resp.Data == nil {
		t.Fatal("expected data to not be nil")
	}

	if resp.Data["tester1@example.com"] == nil {
		t.Fatal("expected map to not be nil")
	}
	tester1CheckOut := resp.Data["tester1@example.com"].(map[string]interface{})
	tester1Available := tester1CheckOut["available"].(bool)

	if resp.Data["tester2@example.com"] == nil {
		t.Fatal("expected map to not be nil")
	}
	tester2CheckOut := resp.Data["tester2@example.com"].(map[string]interface{})
	tester2Available := tester2CheckOut["available"].(bool)

	if tester1Available && tester2Available {
		t.Fatal("one of the testers should not be available")
	}
}

func NormalCheckIn(t *testing.T) {
	testSecretClient.Clear()

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      libraryPrefix + "test-set/check-in",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	checkIns := resp.Data["check_ins"].([]string)
	if len(checkIns) != 1 {
		t.Fatal("expected 1 check-in")
	}

	if testSecretClient.disableAccountCalls != 1 {
		t.Fatalf("Disabled account method should be called once")
	}
}

func ForceCheckIn(t *testing.T) {
	testSecretClient.Clear()

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      libraryPrefix + "manage/test-set/check-in",
		Storage:   testStorage,
	}
	resp, err := testBackend.HandleRequest(ctx, req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
	checkIns := resp.Data["check_ins"].([]string)
	if len(checkIns) != 1 {
		t.Fatal("expected 1 check-in")
	}

	if testSecretClient.disableAccountCalls != 1 {
		t.Fatalf("Disabled account method should be called once")
	}
}
