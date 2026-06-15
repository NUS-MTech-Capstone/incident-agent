package ddm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/NUS-MTech-Capstone/incident-agent/internal/model"
)

type Client struct {
	controlPlaneURL   string
	workloadTokenFile string
	client            *http.Client
}

type Run struct {
	RunID           string    `json:"runId"`
	IncidentID      string    `json:"incidentId"`
	HostID          string    `json:"hostId"`
	OperationsURL   string    `json:"operationsUrl"`
	CapabilityToken string    `json:"capabilityToken"`
	TokenExpiresAt  time.Time `json:"tokenExpiresAt"`
}

func New(controlPlaneURL, workloadTokenFile string, timeout time.Duration) *Client {
	return &Client{
		controlPlaneURL:   strings.TrimRight(controlPlaneURL, "/"),
		workloadTokenFile: workloadTokenFile, client: &http.Client{Timeout: timeout},
	}
}

func (c *Client) StartRun(ctx context.Context, incidentID, hostID string, operations []string) (Run, error) {
	return c.controlRequest(ctx, "/automation/runs/start", map[string]any{
		"incidentId": incidentID, "hostId": hostID, "phase": "diagnose",
		"allowedOperations": operations,
	})
}

func (c *Client) IssueToken(ctx context.Context, runID, phase string, operations []string, planHash string) (Run, error) {
	return c.controlRequest(ctx, "/automation/runs/"+runID+"/token", map[string]any{
		"phase": phase, "allowedOperations": operations, "planHash": planHash,
	})
}

func (c *Client) CloseRun(ctx context.Context, runID, capabilityToken string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.controlPlaneURL+"/automation/runs/"+runID+"/close", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+capabilityToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("control plane close returned status %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) Execute(ctx context.Context, operationsURL, runID, capabilityToken, operationID, planHash string) (model.OperationResult, error) {
	body, err := json.Marshal(map[string]string{"operationId": operationID, "planHash": planHash})
	if err != nil {
		return model.OperationResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(operationsURL, "/")+"/automation/runs/"+runID+"/operations", bytes.NewReader(body))
	if err != nil {
		return model.OperationResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+capabilityToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return model.OperationResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return model.OperationResult{}, fmt.Errorf("dataplane operation returned status %d", resp.StatusCode)
	}
	var result model.OperationResult
	return result, json.NewDecoder(resp.Body).Decode(&result)
}

func (c *Client) controlRequest(ctx context.Context, path string, payload any) (Run, error) {
	token, err := os.ReadFile(c.workloadTokenFile)
	if err != nil {
		return Run{}, fmt.Errorf("read projected workload token: %w", err)
	}
	if strings.TrimSpace(string(token)) == "" {
		return Run{}, errors.New("projected workload token is empty")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Run{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.controlPlaneURL+path, bytes.NewReader(body))
	if err != nil {
		return Run{}, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return Run{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Run{}, fmt.Errorf("control plane returned status %d", resp.StatusCode)
	}
	var run Run
	return run, json.NewDecoder(resp.Body).Decode(&run)
}
