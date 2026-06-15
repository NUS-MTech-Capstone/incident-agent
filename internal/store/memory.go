package store

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/NUS-MTech-Capstone/incident-agent/internal/model"
)

type Memory struct {
	mu        sync.Mutex
	incidents map[string]model.Incident
	sources   map[string]string
	now       func() time.Time
	next      int
}

func NewMemory() *Memory {
	return &Memory{incidents: map[string]model.Incident{}, sources: map[string]string{}, now: time.Now}
}

func (s *Memory) Create(_ context.Context, alert model.Alert) (model.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sources[alert.SourceID]; ok {
		return model.Incident{}, ErrDuplicate
	}
	s.next++
	now := s.now().UTC()
	incident := model.Incident{
		ID: fmt.Sprintf("inc-%d", s.next), SourceID: alert.SourceID, AlarmARN: alert.AlarmARN,
		AlarmName: alert.AlarmName, HostID: alert.HostID, RunbookVersion: alert.RunbookVersion,
		State: model.StateDiagnosing, Reason: alert.Reason, CreatedAt: now, UpdatedAt: now,
	}
	s.incidents[incident.ID] = incident
	s.sources[alert.SourceID] = incident.ID
	return incident, nil
}

func (s *Memory) Get(_ context.Context, id string) (model.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	incident, ok := s.incidents[id]
	if !ok {
		return model.Incident{}, ErrNotFound
	}
	return incident, nil
}

func (s *Memory) List(_ context.Context, limit int) ([]model.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]model.Incident, 0, len(s.incidents))
	for _, incident := range s.incidents {
		result = append(result, incident)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (s *Memory) SetDiagnosis(_ context.Context, id, runID, operationsURL string, evidence []model.OperationResult, plan model.Plan, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	incident, ok := s.incidents[id]
	if !ok {
		return ErrNotFound
	}
	if incident.State != model.StateDiagnosing {
		return ErrConflict
	}
	incident.RunID, incident.OperationsURL = runID, operationsURL
	incident.Evidence, incident.Plan, incident.PlanHash = evidence, plan, hash
	if len(plan.Actions) == 0 {
		incident.State = model.StateCompleted
		incident.Report = "Diagnosis completed. No remediation action was proposed."
	} else {
		incident.State = model.StateAwaitingApproval
	}
	incident.UpdatedAt = s.now().UTC()
	s.incidents[id] = incident
	return nil
}

func (s *Memory) SetFailure(_ context.Context, id, message string) error {
	return s.update(id, func(incident *model.Incident) error {
		if incident.State == model.StateRecovered || incident.State == model.StateCompleted ||
			incident.State == model.StateRejected {
			return ErrConflict
		}
		incident.State, incident.ErrorMessage = model.StateFailed, message
		return nil
	})
}

func (s *Memory) RecoverByAlarm(_ context.Context, alarmARN string) ([]model.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var recovered []model.Incident
	for id, incident := range s.incidents {
		if incident.AlarmARN == alarmARN &&
			(incident.State == model.StateDiagnosing || incident.State == model.StateAwaitingApproval) {
			incident.State = model.StateRecovered
			incident.Report = "CloudWatch returned to OK before remediation approval."
			incident.UpdatedAt = s.now().UTC()
			s.incidents[id] = incident
			recovered = append(recovered, incident)
		}
	}
	return recovered, nil
}

func (s *Memory) Approve(_ context.Context, id, planHash, subject string) error {
	return s.decide(id, planHash, subject, "APPROVED", model.StateExecuting)
}

func (s *Memory) Reject(_ context.Context, id, planHash, subject string) error {
	return s.decide(id, planHash, subject, "REJECTED", model.StateRejected)
}

func (s *Memory) decide(id, planHash, subject, decision, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	incident, ok := s.incidents[id]
	if !ok {
		return ErrNotFound
	}
	if incident.State != model.StateAwaitingApproval || incident.PlanHash != planHash {
		return ErrConflict
	}
	now := s.now().UTC()
	incident.State, incident.ApproverSubject = state, subject
	incident.ApprovalDecision, incident.ApprovalAt = decision, &now
	incident.UpdatedAt = now
	s.incidents[id] = incident
	return nil
}

func (s *Memory) SetExecuting(_ context.Context, id string) error {
	return s.update(id, func(incident *model.Incident) error {
		if incident.State != model.StateExecuting {
			return ErrConflict
		}
		return nil
	})
}

func (s *Memory) SetReport(_ context.Context, id, state, report, errorMessage string) error {
	return s.update(id, func(incident *model.Incident) error {
		incident.State, incident.Report, incident.ErrorMessage = state, report, errorMessage
		return nil
	})
}

func (s *Memory) update(id string, change func(*model.Incident) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	incident, ok := s.incidents[id]
	if !ok {
		return ErrNotFound
	}
	if err := change(&incident); err != nil {
		return err
	}
	incident.UpdatedAt = s.now().UTC()
	s.incidents[id] = incident
	return nil
}
