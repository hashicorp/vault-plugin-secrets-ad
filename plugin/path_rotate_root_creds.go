package plugin

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) pathRotateCredentials() *framework.Path {
	return &framework.Path{
		Pattern: "rotate-root",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback:                    b.pathRotateCredentialsUpdate,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback:                    b.pathRotateCredentialsUpdate,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.pathRotateCredentialsUpdate,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},

		HelpSynopsis:    pathRotateCredentialsUpdateHelpSyn,
		HelpDescription: pathRotateCredentialsUpdateHelpDesc,
	}
}

func (b *backend) pathRotateCredentialsUpdate(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	engineConf, err := readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if engineConf == nil {
		return nil, errors.New("the config is currently unset")
	}

	newPassword, err := GeneratePassword(ctx, engineConf.PasswordConf, b.System())
	if err != nil {
		return nil, err
	}
	oldPassword := engineConf.ADConf.BindPassword

	if !atomic.CompareAndSwapInt32(b.rotateRootLock, 0, 1) {
		resp := &logical.Response{}
		resp.AddWarning("Root password rotation is already in progress.")
		return resp, nil
	}
	defer atomic.CompareAndSwapInt32(b.rotateRootLock, 1, 0)

	// Update the password remotely.
	if err := b.client.UpdateRootPassword(engineConf.ADConf, engineConf.ADConf.BindDN, newPassword); err != nil {
		return nil, err
	}
	engineConf.ADConf.BindPassword = newPassword

	// Update the password locally.
	if pwdStoringErr := writeConfig(ctx, req.Storage, engineConf); pwdStoringErr != nil {
		// We were unable to store the new password locally. We can't continue in this state because we won't be able
		// to roll any passwords, including our own to get back into a state of working. So, we need to roll back to
		// the last password we successfully got into storage.
		if rollbackErr := b.rollBackPassword(ctx, engineConf, oldPassword); rollbackErr != nil {
			return nil, fmt.Errorf("unable to store new password due to %s and unable to return to previous password due to %s, configure a new binddn and bindpass to restore active directory function", pwdStoringErr, rollbackErr)
		}
		return nil, fmt.Errorf("unable to update password due to storage err: %s", pwdStoringErr)
	}
	// Respond with a 204.
	return nil, nil
}

// rollBackPassword uses naive exponential backoff to retry updating to an old password,
// because Active Directory may still be propagating the previous password change.
func (b *backend) rollBackPassword(ctx context.Context, engineConf *configuration, oldPassword string) error {
	var err error
	for i := 0; i < 10; i++ {
		waitSeconds := math.Pow(float64(i), 2)
		timer := time.NewTimer(time.Duration(waitSeconds) * time.Second)
		select {
		case <-timer.C:
		case <-ctx.Done():
			// Outer environment is closing.
			return fmt.Errorf("unable to roll back password because enclosing environment is shutting down")
		}
		if err = b.client.UpdateRootPassword(engineConf.ADConf, engineConf.ADConf.BindDN, oldPassword); err == nil {
			// Success.
			return nil
		}
	}
	// Failure after looping.
	return err
}

const pathRotateCredentialsUpdateHelpSyn = `
Request to rotate the root credentials.
`

const pathRotateCredentialsUpdateHelpDesc = `
This path attempts to rotate the root credentials. 
`
