package alerts

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NUS-MTech-Capstone/incident-agent/internal/model"
)

type snsEnvelope struct {
	MessageID string `json:"MessageId"`
	Message   string `json:"Message"`
}

type cloudWatchAlarm struct {
	AlarmName        string `json:"AlarmName"`
	AlarmDescription string `json:"AlarmDescription"`
	AlarmARN         string `json:"AlarmArn"`
	NewStateValue    string `json:"NewStateValue"`
	NewStateReason   string `json:"NewStateReason"`
	StateChangeTime  string `json:"StateChangeTime"`
}

type alarmMetadata struct {
	HostID         string `json:"hostId"`
	RunbookVersion string `json:"runbookVersion"`
}

func ParseSQSBody(body string) (model.Alert, error) {
	var envelope snsEnvelope
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return model.Alert{}, fmt.Errorf("decode SNS envelope: %w", err)
	}
	if envelope.MessageID == "" || envelope.Message == "" {
		return model.Alert{}, errors.New("SNS envelope is incomplete")
	}
	var alarm cloudWatchAlarm
	if err := json.Unmarshal([]byte(envelope.Message), &alarm); err != nil {
		return model.Alert{}, fmt.Errorf("decode CloudWatch alarm: %w", err)
	}
	if alarm.AlarmARN == "" || alarm.AlarmName == "" ||
		(alarm.NewStateValue != "ALARM" && alarm.NewStateValue != "OK") {
		return model.Alert{}, errors.New("unsupported CloudWatch alarm notification")
	}
	var metadata alarmMetadata
	if err := json.Unmarshal([]byte(alarm.AlarmDescription), &metadata); err != nil {
		return model.Alert{}, fmt.Errorf("alarm description must be JSON metadata: %w", err)
	}
	if metadata.HostID == "" {
		return model.Alert{}, errors.New("alarm metadata hostId is required")
	}
	occurredAt, err := parseStateChangeTime(alarm.StateChangeTime)
	if err != nil {
		return model.Alert{}, fmt.Errorf("parse alarm state change time: %w", err)
	}
	return model.Alert{
		SourceID: alarm.AlarmARN + "|" + alarm.StateChangeTime + "|" + alarm.NewStateValue,
		AlarmARN: alarm.AlarmARN, AlarmName: alarm.AlarmName, State: alarm.NewStateValue,
		Reason: alarm.NewStateReason, HostID: metadata.HostID,
		RunbookVersion: metadata.RunbookVersion, OccurredAt: occurredAt.UTC(),
	}, nil
}

func parseStateChangeTime(value string) (time.Time, error) {
	formats := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.999999999-0700",
	}
	var lastErr error
	for _, format := range formats {
		parsed, err := time.Parse(format, value)
		if err == nil {
			return parsed, nil
		}
		lastErr = err
	}
	return time.Time{}, lastErr
}
