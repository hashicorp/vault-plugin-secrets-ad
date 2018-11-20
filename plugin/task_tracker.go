package plugin

// TODO move to Vault helper when this is nailed.
// package in vault would be expiration

import (
	"context"
	"fmt"
	"time"

	"github.com/go-errors/errors"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/logical"
)

const taskTrackerStorageKey = "tasktracker"

// NewTaskTracker creates an object to handle tasks on a per-backend level.
// Its chief use is for rotating and revoking static credentials
// that are returned multiple times by a particular backend.
func NewTaskTracker(logger hclog.Logger, backendUUID string) *TaskTracker {
	return &TaskTracker{
		logger:      logger.Named(taskTrackerStorageKey),
		backendUUID: backendUUID,
	}
}

type TaskTracker struct {
	logger      hclog.Logger
	backendUUID string
}

func (t *TaskTracker) Upsert(ctx context.Context, storage logical.Storage, task *Task) error {
	storageKey, err := taskStorageKey(t.backendUUID, task)
	if err != nil {
		return err
	}
	entry, err := logical.StorageEntryJSON(storageKey, task)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// PeriodicFunc fulfills an interface by the same name on framework.Backend.
// It is run by the Rollback TaskTracker and can be expected to be started once a minute.
func (t *TaskTracker) PeriodicFunc(ctx context.Context, req *logical.Request) error {

	start := time.Now()
	var errs *multierror.Error

	for _, taskType := range []TaskType{TaskTypeRotation, TaskTypeRevocation} {

		taskKeys, err := req.Storage.List(ctx, taskListKey(t.backendUUID, taskType))
		if err != nil {
			if t.logger.IsWarn() {
				t.logger.Warn("unable to list task keys: %s", err)
			}
			errs = multierror.Append(errs, err)
		}

		for _, taskKey := range taskKeys {
			entry, err := req.Storage.Get(ctx, taskKey)
			if err != nil {
				if t.logger.IsWarn() {
					t.logger.Warn("unable to retrieve task key %s due to %s", taskKey, err)
				}
				continue
			}
			task := &Task{}
			if err := entry.DecodeJSON(entry); err != nil {
				if t.logger.IsWarn() {
					t.logger.Warn("unable to decode task key %s due to %s", taskKey, err)
				}
				continue
			}
			if task.ExecuteAfter.After(start) {
				continue
			}
			if err := task.Execute(ctx, req); err != nil {
				if t.logger.IsWarn() {
					t.logger.Warn("unable to execute %s: %s", task.Identifier, err)
				}
				errs = multierror.Append(errs, err)
			}
			if t.logger.IsDebug() {
				t.logger.Debug("executed %+v", task)
			}
			if err := req.Storage.Delete(ctx, taskKey); err != nil {
				if t.logger.IsWarn() {
					t.logger.Warn("unable to delete %s: %s", task.Identifier, err)
				}
			}
		}
	}
	return errs.ErrorOrNil()
}

type Task struct {
	Identifier   string
	Type         TaskType
	ExecuteAfter time.Time
	Execute      func(ctx context.Context, req *logical.Request) error
}

func (t *Task) Validate() error {
	if t.Identifier == "" {
		return errors.New("identifier is required")
	}
	if t.Type == TaskTypeUnset {
		return errors.New("task type is required")
	}
	if t.ExecuteAfter.Before(time.Now()) {
		return errors.New("time must be in the future")
	}
	if t.Execute == nil {
		return errors.New("rotation function must be populated")
	}
	return nil
}

type TaskType int

const (
	TaskTypeUnset TaskType = iota
	TaskTypeRotation
	TaskTypeRevocation
)

func (t TaskType) String() string {
	switch t {
	case TaskTypeRotation:
		return "rotation"
	case TaskTypeRevocation:
		return "revocation"
	default:
		return ""
	}
}

func taskListKey(backendUUID string, taskType TaskType) string {
	return fmt.Sprintf("%s/%s/%s/", taskTrackerStorageKey, backendUUID, taskType.String())
}

func taskStorageKey(backendUUID string, task *Task) (string, error) {
	// If the task isn't valid, we're not going to be able to build a safe
	// storage key.
	if err := task.Validate(); err != nil {
		return "", err
	}

	// - The taskTrackerStorageKey field is included to namespace everything for these task managers.
	// - The backendUUID is included because there may be multiple instances of the expiration manager,
	//     and we don't want different managers to clobber each other's storage.
	//     We prevent this by using the mount path, which will differ for each instance of a backend.
	// - The type field is included because there may be up to one revocation task and up to one rotation task.
	// - The identifier is included so its key will replace any previous tasks with the same identifier.
	return fmt.Sprintf("%s/%s/%s/%s", taskTrackerStorageKey, backendUUID, task.Type.String(), task.Identifier), nil
}
