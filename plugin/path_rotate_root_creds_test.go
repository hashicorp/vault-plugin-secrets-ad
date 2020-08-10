package plugin

import (
	"testing"
	"time"

	"github.com/go-errors/errors"
	"github.com/hashicorp/vault-plugin-secrets-ad/plugin/client"
	"github.com/hashicorp/vault/sdk/helper/ldaputil"
)

func TestRollBackPassword(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	b := testBackend
	doneChan := make(chan struct{})
	ctx := &testContext{doneChan}
	testConf := &configuration{
		ADConf: &client.ADConf{
			ConfigEntry: &ldaputil.ConfigEntry{
				BindDN: "cats",
			},
		},
	}

	// Test succeeds immediately with successful response.
	if err := b.rollBackPassword(ctx, testConf, "testing"); err != nil {
		t.Fatal(err)
	}

	b.client = &badFake{}

	// Test can be that retrying can be interrupted after 10 seconds using ctx.
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		b.rollBackPassword(ctx, testConf, "testing")
	}()

	// Wait 30 seconds and then close the doneChan, which should cause rollback to stop.
	timer := time.NewTimer(time.Second * 30)
	select {
	case <-timer.C:
		close(doneChan)
	}

	timer.Reset(time.Second)
	select {
	case <-timer.C:
		t.Fatal("should have stopped by now")
	case <-stopped:
		// pass
	}
}

type testContext struct {
	doneChan chan struct{}
}

func (c *testContext) Deadline() (deadline time.Time, ok bool) {
	return time.Time{}, false
}

func (c *testContext) Done() <-chan struct{} {
	return c.doneChan
}

func (c *testContext) Err() error {
	return nil
}

func (c *testContext) Value(key interface{}) interface{} {
	return nil
}

type badFake struct{}

func (f *badFake) Get(conf *client.ADConf, serviceAccountName string) (*client.Entry, error) {
	return nil, errors.New("nope")
}

func (f *badFake) GetPasswordLastSet(conf *client.ADConf, serviceAccountName string) (time.Time, error) {
	return time.Time{}, errors.New("nope")
}

func (f *badFake) UpdatePassword(conf *client.ADConf, serviceAccountName string, newPassword string) error {
	return errors.New("nope")
}

func (f *badFake) UpdateRootPassword(conf *client.ADConf, bindDN string, newPassword string) error {
	return errors.New("nope")
}

func (f *badFake) EnableAccount(conf *client.ADConf, serviceAccountName string) error {
	return errors.New("nope")
}

func (f *badFake) DisableAccount(conf *client.ADConf, serviceAccountName string) error {
	return errors.New("nope")
}
