package alerts

import (
	"encoding/json"
	"testing"
)

func TestParseSQSBody(t *testing.T) {
	alarm, _ := json.Marshal(map[string]string{
		"AlarmName": "high-cpu", "AlarmArn": "arn:alarm:1", "NewStateValue": "ALARM",
		"NewStateReason": "CPU exceeded threshold", "StateChangeTime": "2026-06-15T10:00:00.123Z",
		"AlarmDescription": `{"hostId":"host-1","runbookVersion":"v1"}`,
	})
	envelope, _ := json.Marshal(map[string]string{"MessageId": "message-1", "Message": string(alarm)})
	got, err := ParseSQSBody(string(envelope))
	if err != nil {
		t.Fatal(err)
	}
	if got.HostID != "host-1" || got.State != "ALARM" || got.SourceID == "" {
		t.Fatalf("alert = %#v", got)
	}
}

func TestParseSQSBodyRejectsMissingHost(t *testing.T) {
	alarm, _ := json.Marshal(map[string]string{
		"AlarmName": "high-cpu", "AlarmArn": "arn:alarm:1", "NewStateValue": "ALARM",
		"StateChangeTime": "2026-06-15T10:00:00Z", "AlarmDescription": `{}`,
	})
	envelope, _ := json.Marshal(map[string]string{"MessageId": "message-1", "Message": string(alarm)})
	if _, err := ParseSQSBody(string(envelope)); err == nil {
		t.Fatal("ParseSQSBody accepted missing hostId")
	}
}

func TestParseSQSBodyAcceptsCloudWatchOffsetTimestamp(t *testing.T) {
	alarm, _ := json.Marshal(map[string]string{
		"AlarmName": "high-cpu", "AlarmArn": "arn:alarm:1", "NewStateValue": "ALARM",
		"StateChangeTime":  "2026-06-15T10:00:00.123+0000",
		"AlarmDescription": `{"hostId":"host-1","runbookVersion":"v1"}`,
	})
	envelope, _ := json.Marshal(map[string]string{"MessageId": "message-1", "Message": string(alarm)})
	if _, err := ParseSQSBody(string(envelope)); err != nil {
		t.Fatal(err)
	}
}
