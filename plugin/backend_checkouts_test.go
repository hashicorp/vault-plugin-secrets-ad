package plugin

import (
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// The AD library of service accounts that can be checked out
// is a discrete set of features. This test suite provides
// end-to-end tests of these interrelated endpoints.
func TestCheckOuts(t *testing.T) {
	// Plant a config.
	t.Run("plant config", PlantConfig)

	// Exercise all set endpoints.
	t.Run("write set", WriteReserve)
	t.Run("read set", ReadReserve)
	t.Run("read set status", ReadReserveStatus)
	t.Run("write set toggle off", WriteReserveToggleOff)
	t.Run("read set toggle off", ReadReserveToggleOff)
	t.Run("write conflicting set", WriteReserveWithConflictingServiceAccounts)
	t.Run("list sets", ListReserves)
	t.Run("delete set", DeleteReserve)

	// Do some common updates on sets and ensure they work.
	t.Run("write set", WriteReserve)
	t.Run("add service account", AddAnotherServiceAccount)
	t.Run("remove service account", RemoveServiceAccount)
}

func WriteReserve(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      libraryPrefix + "test-set",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"service_account_names":        []string{"tester1@example.com", "tester2@example.com"},
			"ttl":                          "10h",
			"max_ttl":                      "11h",
			"disable_check_in_enforcement": true,
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

func ReadReserve(t *testing.T) {
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
	ttl := resp.Data["ttl"].(int64)
	if ttl != 10*60*60 { // 10 hours
		t.Fatal(ttl)
	}
	maxTTL := resp.Data["max_ttl"].(int64)
	if maxTTL != 11*60*60 { // 11 hours
		t.Fatal(maxTTL)
	}
}

func WriteReserveToggleOff(t *testing.T) {
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

func ReadReserveToggleOff(t *testing.T) {
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

func ReadReserveStatus(t *testing.T) {
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
	testerStatus := resp.Data["tester1@example.com"].(map[string]interface{})
	if !testerStatus["available"].(bool) {
		t.Fatal("should be available for checkout")
	}
}

func WriteReserveWithConflictingServiceAccounts(t *testing.T) {
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

func ListReserves(t *testing.T) {
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
	listedKeys := resp.Data["keys"].([]string)
	if len(listedKeys) != 1 {
		t.Fatalf("expected 1 key but received %s", listedKeys)
	}
	if "test-set" != listedKeys[0] {
		t.Fatal("expected test-set to be the only listed item")
	}
}

func DeleteReserve(t *testing.T) {
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
