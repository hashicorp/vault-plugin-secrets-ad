package plugin

import (
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestCanCheckIn(t *testing.T) {
	can := canCheckIn(&logical.Request{}, &CheckOut{}, true)
	if !can {
		t.Fatal("failing because check-in enforcement should be overridden")
	}
	can = canCheckIn(&logical.Request{EntityID: "foo"}, &CheckOut{BorrowerEntityID: "foo"}, false)
	if !can {
		t.Fatal("the entity that checked out the secret should be able to check it in")
	}
	can = canCheckIn(&logical.Request{ClientToken: "foo"}, &CheckOut{BorrowerClientToken: "foo"}, false)
	if !can {
		t.Fatal("the client token that checked out the secret should be able to check it in")
	}
	can = canCheckIn(&logical.Request{EntityID: "fizz"}, &CheckOut{BorrowerEntityID: "buzz"}, false)
	if can {
		t.Fatal("other entities shouldn't be able to perform check-ins")
	}
	can = canCheckIn(&logical.Request{ClientToken: "fizz"}, &CheckOut{BorrowerClientToken: "buzz"}, false)
	if can {
		t.Fatal("other tokens shouldn't be able to perform check-ins")
	}
	can = canCheckIn(&logical.Request{}, &CheckOut{}, false)
	if can {
		t.Fatal("when insufficient auth info is provided, check-in should not be allowed")
	}
}
