package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NUS-MTech-Capstone/incident-agent/internal/model"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type Postgres struct {
	db  *sql.DB
	now func() time.Time
}

func NewPostgres(ctx context.Context, databaseURL string) (*Postgres, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	store := &Postgres{db: db, now: time.Now}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Postgres) Close() error { return s.db.Close() }

func (s *Postgres) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS incidents (
	id TEXT PRIMARY KEY,
	source_id TEXT NOT NULL UNIQUE,
	alarm_arn TEXT NOT NULL,
	alarm_name TEXT NOT NULL,
	host_id TEXT NOT NULL,
	runbook_version TEXT NOT NULL DEFAULT '',
	state TEXT NOT NULL,
	reason TEXT NOT NULL DEFAULT '',
	run_id TEXT NOT NULL DEFAULT '',
	operations_url TEXT NOT NULL DEFAULT '',
	evidence_json JSONB NOT NULL DEFAULT '[]',
	plan_json JSONB NOT NULL DEFAULT '{}',
	plan_hash TEXT NOT NULL DEFAULT '',
	approver_subject TEXT NOT NULL DEFAULT '',
	approval_decision TEXT NOT NULL DEFAULT '',
	approval_at TIMESTAMPTZ,
	report TEXT NOT NULL DEFAULT '',
	error_message TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS incidents_alarm_idx ON incidents (alarm_arn, created_at DESC);
CREATE INDEX IF NOT EXISTS incidents_state_idx ON incidents (state, updated_at DESC);
`)
	if err != nil {
		return fmt.Errorf("migrate incident store: %w", err)
	}
	return nil
}

func (s *Postgres) Create(ctx context.Context, alert model.Alert) (model.Incident, error) {
	id, err := incidentID()
	if err != nil {
		return model.Incident{}, err
	}
	now := s.now().UTC()
	incident := model.Incident{
		ID: id, SourceID: alert.SourceID, AlarmARN: alert.AlarmARN, AlarmName: alert.AlarmName,
		HostID: alert.HostID, RunbookVersion: alert.RunbookVersion, State: model.StateDiagnosing,
		Reason: alert.Reason, CreatedAt: now, UpdatedAt: now,
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO incidents (
	id, source_id, alarm_arn, alarm_name, host_id, runbook_version,
	state, reason, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
`, incident.ID, incident.SourceID, incident.AlarmARN, incident.AlarmName, incident.HostID,
		incident.RunbookVersion, incident.State, incident.Reason, incident.CreatedAt, incident.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return model.Incident{}, ErrDuplicate
		}
		return model.Incident{}, fmt.Errorf("create incident: %w", err)
	}
	return incident, nil
}

func (s *Postgres) Get(ctx context.Context, id string) (model.Incident, error) {
	return scanIncident(s.db.QueryRowContext(ctx, incidentSelect+` WHERE id = $1`, id))
}

func (s *Postgres) List(ctx context.Context, limit int) ([]model.Incident, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, incidentSelect+` ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var incidents []model.Incident
	for rows.Next() {
		incident, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		incidents = append(incidents, incident)
	}
	return incidents, rows.Err()
}

func (s *Postgres) SetDiagnosis(ctx context.Context, id, runID, operationsURL string, evidence []model.OperationResult, plan model.Plan, hash string) error {
	evidenceJSON, _ := json.Marshal(evidence)
	planJSON, _ := json.Marshal(plan)
	state := model.StateAwaitingApproval
	report := ""
	if len(plan.Actions) == 0 {
		state = model.StateCompleted
		report = "Diagnosis completed. No remediation action was proposed."
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE incidents SET run_id=$1, operations_url=$2, evidence_json=$3, plan_json=$4,
	plan_hash=$5, state=$6, report=$7, updated_at=$8
WHERE id=$9 AND state=$10
`, runID, operationsURL, evidenceJSON, planJSON, hash, state, report, s.now().UTC(), id, model.StateDiagnosing)
	return classifyUpdate(result, err)
}

func (s *Postgres) SetFailure(ctx context.Context, id, message string) error {
	result, err := s.db.ExecContext(ctx, `
UPDATE incidents SET state=$1,error_message=$2,updated_at=$3
WHERE id=$4 AND state IN ($5,$6)
`, model.StateFailed, message, s.now().UTC(), id, model.StateDiagnosing, model.StateExecuting)
	return classifyUpdate(result, err)
}

func (s *Postgres) RecoverByAlarm(ctx context.Context, alarmARN string) ([]model.Incident, error) {
	rows, err := s.db.QueryContext(ctx, `
UPDATE incidents SET state=$1,report=$2,updated_at=$3
WHERE alarm_arn=$4 AND state IN ($5,$6)
RETURNING id,source_id,alarm_arn,alarm_name,host_id,runbook_version,state,reason,
	run_id,operations_url,evidence_json,plan_json,plan_hash,approver_subject,
	approval_decision,approval_at,report,error_message,created_at,updated_at
`, model.StateRecovered, "CloudWatch returned to OK before remediation approval.",
		s.now().UTC(), alarmARN, model.StateDiagnosing, model.StateAwaitingApproval)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var recovered []model.Incident
	for rows.Next() {
		incident, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		recovered = append(recovered, incident)
	}
	return recovered, rows.Err()
}

func (s *Postgres) Approve(ctx context.Context, id, planHash, subject string) error {
	return s.decision(ctx, id, planHash, subject, "APPROVED", model.StateExecuting)
}

func (s *Postgres) Reject(ctx context.Context, id, planHash, subject string) error {
	return s.decision(ctx, id, planHash, subject, "REJECTED", model.StateRejected)
}

func (s *Postgres) decision(ctx context.Context, id, planHash, subject, decision, state string) error {
	now := s.now().UTC()
	result, err := s.db.ExecContext(ctx, `
UPDATE incidents SET state=$1,approver_subject=$2,approval_decision=$3,approval_at=$4,updated_at=$4
WHERE id=$5 AND state=$6 AND plan_hash=$7
`, state, subject, decision, now, id, model.StateAwaitingApproval, planHash)
	return classifyUpdate(result, err)
}

func (s *Postgres) SetExecuting(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE incidents SET updated_at=$1 WHERE id=$2 AND state=$3`,
		s.now().UTC(), id, model.StateExecuting)
	return classifyUpdate(result, err)
}

func (s *Postgres) SetReport(ctx context.Context, id, state, report, errorMessage string) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE incidents SET state=$1,report=$2,error_message=$3,updated_at=$4 WHERE id=$5
`, state, report, errorMessage, s.now().UTC(), id)
	return err
}

const incidentSelect = `
SELECT id,source_id,alarm_arn,alarm_name,host_id,runbook_version,state,reason,
	run_id,operations_url,evidence_json,plan_json,plan_hash,approver_subject,
	approval_decision,approval_at,report,error_message,created_at,updated_at
FROM incidents`

type rowScanner interface{ Scan(...any) error }

func scanIncident(row rowScanner) (model.Incident, error) {
	var incident model.Incident
	var evidenceJSON, planJSON []byte
	err := row.Scan(
		&incident.ID, &incident.SourceID, &incident.AlarmARN, &incident.AlarmName,
		&incident.HostID, &incident.RunbookVersion, &incident.State, &incident.Reason,
		&incident.RunID, &incident.OperationsURL, &evidenceJSON, &planJSON,
		&incident.PlanHash, &incident.ApproverSubject, &incident.ApprovalDecision,
		&incident.ApprovalAt, &incident.Report, &incident.ErrorMessage,
		&incident.CreatedAt, &incident.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Incident{}, ErrNotFound
	}
	if err != nil {
		return model.Incident{}, err
	}
	if err := json.Unmarshal(evidenceJSON, &incident.Evidence); err != nil {
		return model.Incident{}, err
	}
	if len(planJSON) > 0 && string(planJSON) != "{}" {
		if err := json.Unmarshal(planJSON, &incident.Plan); err != nil {
			return model.Incident{}, err
		}
	}
	return incident, nil
}

func classifyUpdate(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrConflict
	}
	return nil
}

func incidentID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "inc-" + hex.EncodeToString(value[:]), nil
}

func isUniqueViolation(err error) bool {
	return err != nil && (contains(err.Error(), "SQLSTATE 23505") || contains(err.Error(), "duplicate key"))
}

func contains(value, part string) bool {
	for i := 0; i+len(part) <= len(value); i++ {
		if value[i:i+len(part)] == part {
			return true
		}
	}
	return false
}
