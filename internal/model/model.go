package model

import "time"

const (
	StateDiagnosing       = "DIAGNOSING"
	StateAwaitingApproval = "AWAITING_APPROVAL"
	StateExecuting        = "EXECUTING"
	StateCompleted        = "COMPLETED"
	StateRejected         = "REJECTED"
	StateRecovered        = "RECOVERED"
	StateFailed           = "FAILED"
)

type Alert struct {
	SourceID       string
	AlarmARN       string
	AlarmName      string
	State          string
	Reason         string
	HostID         string
	RunbookVersion string
	OccurredAt     time.Time
}

type Action struct {
	OperationID string `json:"operationId"`
	Reason      string `json:"reason"`
}

type Plan struct {
	Summary   string   `json:"summary"`
	Rationale string   `json:"rationale"`
	Actions   []Action `json:"actions"`
}

type OperationResult struct {
	OperationID string `json:"operationId"`
	Stdout      string `json:"stdout"`
	Stderr      string `json:"stderr"`
	ExitCode    int    `json:"exitCode"`
}

type Incident struct {
	ID               string
	SourceID         string
	AlarmARN         string
	AlarmName        string
	HostID           string
	RunbookVersion   string
	State            string
	Reason           string
	RunID            string
	OperationsURL    string
	Evidence         []OperationResult
	Plan             Plan
	PlanHash         string
	ApproverSubject  string
	ApprovalDecision string
	ApprovalAt       *time.Time
	Report           string
	ErrorMessage     string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}
