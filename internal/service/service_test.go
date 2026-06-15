package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/NUS-MTech-Capstone/incident-agent/internal/ddm"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/model"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/store"
)

type fakePlanner struct{ plan model.Plan }

func (f fakePlanner) Plan(context.Context, model.Incident, []model.OperationResult) (model.Plan, error) {
	return f.plan, nil
}

type fakeDDM struct {
	mu         sync.Mutex
	operations []string
	closes     int
}

func (f *fakeDDM) StartRun(context.Context, string, string, []string) (ddm.Run, error) {
	return ddm.Run{RunID: "run-1", OperationsURL: "http://pod", CapabilityToken: "diagnose"}, nil
}

func (f *fakeDDM) IssueToken(_ context.Context, _ string, phase string, _ []string, _ string) (ddm.Run, error) {
	return ddm.Run{RunID: "run-1", OperationsURL: "http://pod", CapabilityToken: phase}, nil
}

func (f *fakeDDM) Execute(_ context.Context, _, _, _, operation, _ string) (model.OperationResult, error) {
	f.mu.Lock()
	f.operations = append(f.operations, operation)
	f.mu.Unlock()
	return model.OperationResult{OperationID: operation, Stdout: "ok", ExitCode: 0}, nil
}

func (f *fakeDDM) CloseRun(context.Context, string, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	return nil
}

func TestIncidentWorkflowThroughApprovalAndVerification(t *testing.T) {
	st := store.NewMemory()
	remote := &fakeDDM{}
	plan := model.Plan{
		Summary: "restart service", Rationale: "health check failed",
		Actions: []model.Action{{OperationID: "restart_service", Reason: "recover service"}},
	}
	svc := New(st, fakePlanner{plan: plan}, remote, time.Second, 4096)
	alert := model.Alert{
		SourceID: "source-1", AlarmARN: "alarm-1", AlarmName: "unhealthy",
		State: "ALARM", HostID: "host-1",
	}
	if err := svc.HandleAlert(t.Context(), alert); err != nil {
		t.Fatal(err)
	}
	incidents, _ := svc.List(t.Context())
	if len(incidents) != 1 || incidents[0].State != model.StateAwaitingApproval {
		t.Fatalf("incidents = %#v", incidents)
	}
	if err := svc.Approve(t.Context(), incidents[0].ID, incidents[0].PlanHash, "user-1"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		incident, _ := svc.Get(t.Context(), incidents[0].ID)
		if incident.State == model.StateCompleted {
			if incident.ApproverSubject != "user-1" || incident.Report == "" {
				t.Fatalf("completed incident = %#v", incident)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("incident did not complete")
}

func TestPlanHashChangesWithAction(t *testing.T) {
	first, _ := PlanHash(model.Plan{Summary: "a", Rationale: "b"})
	second, _ := PlanHash(model.Plan{
		Summary: "a", Rationale: "b",
		Actions: []model.Action{{OperationID: "restart_service", Reason: "c"}},
	})
	if first == second {
		t.Fatal("plan hashes matched")
	}
}

func TestDiagnosisWithoutActionClosesAutomationRun(t *testing.T) {
	st := store.NewMemory()
	remote := &fakeDDM{}
	svc := New(st, fakePlanner{plan: model.Plan{
		Summary: "healthy", Rationale: "health check succeeded",
	}}, remote, time.Second, 4096)
	if err := svc.HandleAlert(t.Context(), model.Alert{
		SourceID: "source-no-action", AlarmARN: "alarm", AlarmName: "alarm",
		State: "ALARM", HostID: "host",
	}); err != nil {
		t.Fatal(err)
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if remote.closes != 1 {
		t.Fatalf("CloseRun calls = %d, want 1", remote.closes)
	}
}

func TestOKTransitionRecoversAndClosesPendingRun(t *testing.T) {
	st := store.NewMemory()
	remote := &fakeDDM{}
	svc := New(st, fakePlanner{plan: model.Plan{
		Summary: "restart", Rationale: "health check failed",
		Actions: []model.Action{{OperationID: "restart_service", Reason: "recover"}},
	}}, remote, time.Second, 4096)
	alarm := model.Alert{
		SourceID: "source-recovery", AlarmARN: "alarm-recovery", AlarmName: "alarm",
		State: "ALARM", HostID: "host",
	}
	if err := svc.HandleAlert(t.Context(), alarm); err != nil {
		t.Fatal(err)
	}
	alarm.State = "OK"
	if err := svc.HandleAlert(t.Context(), alarm); err != nil {
		t.Fatal(err)
	}
	incidents, err := svc.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if incidents[0].State != model.StateRecovered {
		t.Fatalf("state = %s", incidents[0].State)
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if remote.closes != 1 {
		t.Fatalf("CloseRun calls = %d, want 1", remote.closes)
	}
}
