package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/NUS-MTech-Capstone/incident-agent/internal/ddm"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/model"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/redact"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/store"
)

var diagnostics = []string{
	"system_overview", "disk_usage", "memory_usage", "top_processes",
	"service_status", "service_logs", "health_check",
}

type Planner interface {
	Plan(context.Context, model.Incident, []model.OperationResult) (model.Plan, error)
}

type DDMClient interface {
	StartRun(context.Context, string, string, []string) (ddm.Run, error)
	IssueToken(context.Context, string, string, []string, string) (ddm.Run, error)
	Execute(context.Context, string, string, string, string, string) (model.OperationResult, error)
	CloseRun(context.Context, string, string) error
}

type Service struct {
	store              store.Store
	planner            Planner
	ddm                DDMClient
	operationTimeout   time.Duration
	maxOperationOutput int
}

func New(st store.Store, planner Planner, ddm DDMClient, operationTimeout time.Duration, maxOperationOutput int) *Service {
	return &Service{
		store: st, planner: planner, ddm: ddm,
		operationTimeout: operationTimeout, maxOperationOutput: maxOperationOutput,
	}
}

func (s *Service) HandleAlert(ctx context.Context, alert model.Alert) error {
	if alert.State == "OK" {
		recovered, err := s.store.RecoverByAlarm(ctx, alert.AlarmARN)
		if err != nil {
			return err
		}
		for _, incident := range recovered {
			if incident.RunID == "" {
				continue
			}
			token, tokenErr := s.ddm.IssueToken(ctx, incident.RunID, "verify", []string{"health_check"}, "")
			if tokenErr == nil {
				_ = s.ddm.CloseRun(ctx, incident.RunID, token.CapabilityToken)
			}
		}
		return nil
	}
	alert.Reason = redact.Text(alert.Reason, 4096)
	incident, err := s.store.Create(ctx, alert)
	if errors.Is(err, store.ErrDuplicate) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.diagnose(ctx, incident); err != nil {
		current, getErr := s.store.Get(ctx, incident.ID)
		if getErr != nil || current.State != model.StateRecovered {
			_ = s.store.SetFailure(ctx, incident.ID, safeError(err))
		}
		return err
	}
	return nil
}

func (s *Service) diagnose(ctx context.Context, incident model.Incident) error {
	run, err := s.ddm.StartRun(ctx, incident.ID, incident.HostID, diagnostics)
	if err != nil {
		return fmt.Errorf("start automation run: %w", err)
	}
	keepOpen := false
	defer func() {
		if !keepOpen {
			_ = s.ddm.CloseRun(context.Background(), run.RunID, run.CapabilityToken)
		}
	}()
	evidence := make([]model.OperationResult, 0, len(diagnostics))
	for _, operation := range diagnostics {
		operationCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
		result, err := s.ddm.Execute(operationCtx, run.OperationsURL, run.RunID, run.CapabilityToken, operation, "")
		cancel()
		if err != nil {
			result = model.OperationResult{OperationID: operation, Stderr: safeError(err), ExitCode: -1}
		}
		result.Stdout = redact.Text(result.Stdout, s.maxOperationOutput)
		result.Stderr = redact.Text(result.Stderr, s.maxOperationOutput)
		evidence = append(evidence, result)
	}
	current, err := s.store.Get(ctx, incident.ID)
	if err != nil {
		return err
	}
	if current.State == model.StateRecovered {
		return nil
	}
	plan, err := s.planner.Plan(ctx, incident, evidence)
	if err != nil {
		return err
	}
	plan = sanitizePlan(plan)
	hash, err := PlanHash(plan)
	if err != nil {
		return err
	}
	if err := s.store.SetDiagnosis(ctx, incident.ID, run.RunID, run.OperationsURL, evidence, plan, hash); err != nil {
		return err
	}
	keepOpen = len(plan.Actions) > 0
	return nil
}

func (s *Service) List(ctx context.Context) ([]model.Incident, error) {
	return s.store.List(ctx, 100)
}

func (s *Service) Get(ctx context.Context, id string) (model.Incident, error) {
	return s.store.Get(ctx, id)
}

func (s *Service) Approve(ctx context.Context, id, planHash, subject string) error {
	if err := s.store.Approve(ctx, id, planHash, subject); err != nil {
		return err
	}
	go s.execute(context.WithoutCancel(ctx), id)
	return nil
}

func (s *Service) Reject(ctx context.Context, id, planHash, subject string) error {
	if err := s.store.Reject(ctx, id, planHash, subject); err != nil {
		return err
	}
	incident, err := s.store.Get(ctx, id)
	if err == nil && incident.RunID != "" {
		token, tokenErr := s.ddm.IssueToken(ctx, incident.RunID, "verify", []string{"health_check"}, "")
		if tokenErr == nil {
			_ = s.ddm.CloseRun(ctx, incident.RunID, token.CapabilityToken)
		}
	}
	return nil
}

func (s *Service) execute(ctx context.Context, id string) {
	incident, err := s.store.Get(ctx, id)
	if err != nil {
		return
	}
	if err := s.store.SetExecuting(ctx, id); err != nil {
		return
	}
	token, err := s.ddm.IssueToken(ctx, incident.RunID, "remediate", []string{"restart_service"}, incident.PlanHash)
	if err != nil {
		s.failExecution(ctx, incident, err)
		return
	}
	operationCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	restart, err := s.ddm.Execute(operationCtx, incident.OperationsURL, incident.RunID,
		token.CapabilityToken, "restart_service", incident.PlanHash)
	cancel()
	if err != nil || restart.ExitCode != 0 {
		if err == nil {
			err = fmt.Errorf("restart exited with status %d: %s", restart.ExitCode, restart.Stderr)
		}
		s.failExecution(ctx, incident, err)
		return
	}
	verifyToken, err := s.ddm.IssueToken(ctx, incident.RunID, "verify",
		[]string{"service_status", "health_check"}, "")
	if err != nil {
		s.failExecution(ctx, incident, err)
		return
	}
	var verification []model.OperationResult
	success := true
	for _, operation := range []string{"service_status", "health_check"} {
		operationCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
		result, executeErr := s.ddm.Execute(operationCtx, incident.OperationsURL, incident.RunID,
			verifyToken.CapabilityToken, operation, "")
		cancel()
		if executeErr != nil {
			result = model.OperationResult{OperationID: operation, Stderr: safeError(executeErr), ExitCode: -1}
		}
		result.Stdout = redact.Text(result.Stdout, s.maxOperationOutput)
		result.Stderr = redact.Text(result.Stderr, s.maxOperationOutput)
		verification = append(verification, result)
		if result.ExitCode != 0 {
			success = false
		}
	}
	report := buildReport(incident, restart, verification)
	state := model.StateCompleted
	errorMessage := ""
	if !success {
		state = model.StateFailed
		errorMessage = "post-remediation verification failed"
	}
	if err := s.store.SetReport(ctx, id, state, report, errorMessage); err != nil {
		log.Printf("incident report persistence failed incidentId=%s error=%v", id, err)
	}
	_ = s.ddm.CloseRun(ctx, incident.RunID, verifyToken.CapabilityToken)
}

func (s *Service) failExecution(ctx context.Context, incident model.Incident, err error) {
	_ = s.store.SetReport(ctx, incident.ID, model.StateFailed,
		"Approved remediation could not be completed.", safeError(err))
}

func PlanHash(plan model.Plan) (string, error) {
	encoded, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	return redact.Text(err.Error(), 2048)
}

func sanitizePlan(plan model.Plan) model.Plan {
	plan.Summary = redact.Text(plan.Summary, 2048)
	plan.Rationale = redact.Text(plan.Rationale, 4096)
	for i := range plan.Actions {
		plan.Actions[i].Reason = redact.Text(plan.Actions[i].Reason, 2048)
	}
	return plan
}

func buildReport(incident model.Incident, restart model.OperationResult, verification []model.OperationResult) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "Incident %s on host %s\n\n", incident.ID, incident.HostID)
	fmt.Fprintf(&builder, "Approved plan: %s\n", incident.Plan.Summary)
	fmt.Fprintf(&builder, "Remediation: restart_service exit=%d\n", restart.ExitCode)
	for _, result := range verification {
		fmt.Fprintf(&builder, "Verification: %s exit=%d\n", result.OperationID, result.ExitCode)
	}
	return builder.String()
}
