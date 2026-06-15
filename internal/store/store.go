package store

import (
	"context"
	"errors"

	"github.com/NUS-MTech-Capstone/incident-agent/internal/model"
)

var (
	ErrNotFound  = errors.New("incident not found")
	ErrConflict  = errors.New("incident state conflict")
	ErrDuplicate = errors.New("duplicate alert")
)

type Store interface {
	Create(context.Context, model.Alert) (model.Incident, error)
	Get(context.Context, string) (model.Incident, error)
	List(context.Context, int) ([]model.Incident, error)
	SetDiagnosis(context.Context, string, string, string, []model.OperationResult, model.Plan, string) error
	SetFailure(context.Context, string, string) error
	RecoverByAlarm(context.Context, string) ([]model.Incident, error)
	Approve(context.Context, string, string, string) error
	Reject(context.Context, string, string, string) error
	SetExecuting(context.Context, string) error
	SetReport(context.Context, string, string, string, string) error
}
