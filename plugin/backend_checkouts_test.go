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

	// Exercise all reserve endpoints.
	t.Run("write reserve", WriteReserve)
	t.Run("read reserve", ReadReserve)
	t.Run("write conflicting reserve", WriteReserveWithConflictingServiceAccounts)
	t.Run("list reserves", ListReserves)
	t.Run("delete reserve", DeleteReserve)

	// Do some common updates on reserves and ensure they work.
	t.Run("write reserve", WriteReserve)
	t.Run("add service account", AddAnotherServiceAccount)
	t.Run("remove service account", RemoveServiceAccount)
}

func WriteReserve(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      libraryPrefix + "test-reserve",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"service_account_names": []string{"tester1@example.com", "tester2@example.com"},
			"lending_period":        "10h",
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
		Path:      libraryPrefix + "test-reserve",
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
		Path:      libraryPrefix + "test-reserve",
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
		Path:      libraryPrefix + "test-reserve",
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
}

func WriteReserveWithConflictingServiceAccounts(t *testing.T) {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      libraryPrefix + "test-reserve2",
		Storage:   testStorage,
		Data: map[string]interface{}{
			"service_account_names": "tester1@example.com",
		},
	}
	_, err := testBackend.HandleRequest(ctx, req)
	if err == nil {
		t.Fatal("expected err response because we're adding a service account managed by another reserve")
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
	if "test-reserve" != listedKeys[0] {
		t.Fatal("expected test-reserve to be the only listed item")
	}
}

func DeleteReserve(t *testing.T) {
	req := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      libraryPrefix + "test-reserve",
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
