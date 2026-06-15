package store

import (
	"context"
	"sync"
	"testing"

	"github.com/NUS-MTech-Capstone/incident-agent/internal/model"
)

func TestApprovalIsAtomicAndBoundToPlanHash(t *testing.T) {
	st := NewMemory()
	incident, err := st.Create(t.Context(), model.Alert{SourceID: "source", AlarmARN: "alarm", HostID: "host"})
	if err != nil {
		t.Fatal(err)
	}
	plan := model.Plan{Summary: "restart", Rationale: "service unhealthy", Actions: []model.Action{{OperationID: "restart_service", Reason: "recover"}}}
	if err := st.SetDiagnosis(t.Context(), incident.ID, "run", "http://pod", nil, plan, "hash"); err != nil {
		t.Fatal(err)
	}
	var successes int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if st.Approve(context.Background(), incident.ID, "hash", "user") == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("successful approvals = %d, want 1", successes)
	}
	if err := st.Approve(t.Context(), incident.ID, "changed", "user"); err == nil {
		t.Fatal("approval accepted changed plan hash")
	}
}

func TestRecoverOnlyPendingIncidents(t *testing.T) {
	st := NewMemory()
	incident, _ := st.Create(t.Context(), model.Alert{SourceID: "source", AlarmARN: "alarm", HostID: "host"})
	if _, err := st.RecoverByAlarm(t.Context(), "alarm"); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Get(t.Context(), incident.ID)
	if got.State != model.StateRecovered {
		t.Fatalf("state = %s", got.State)
	}
}
