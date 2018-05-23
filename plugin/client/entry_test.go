package client

import (
	"testing"
	"time"

	"github.com/go-ldap/ldap"
)

// Since `$ make test` is run with the -race flag, this will detect a race and fail if it's racy.
func TestIfEntryCreationIsRacy(t *testing.T) {
	for i := 0; i < 10000; i++ {
		go func() {
			ldapEntry := &ldap.Entry{
				Attributes: []*ldap.EntryAttribute{
					{Name: "hello", Values: []string{"world"}},
				},
			}
			NewEntry(ldapEntry)
		}()
	}
	// Chill out for a second to let everything run.
	time.Sleep(time.Second)
}
