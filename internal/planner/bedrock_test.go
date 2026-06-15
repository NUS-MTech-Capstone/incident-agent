package planner

import (
	"context"
	"testing"

	"github.com/NUS-MTech-Capstone/incident-agent/internal/model"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/document"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

type fakeConverse struct {
	inputs  []*bedrockruntime.ConverseInput
	outputs []*bedrockruntime.ConverseOutput
}

func (f *fakeConverse) Converse(_ context.Context, input *bedrockruntime.ConverseInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error) {
	f.inputs = append(f.inputs, input)
	output := f.outputs[0]
	f.outputs = f.outputs[1:]
	return output, nil
}

func TestBedrockToolProposalUsesBoundedTwoCallLoop(t *testing.T) {
	client := &fakeConverse{outputs: []*bedrockruntime.ConverseOutput{
		{
			Output: &types.ConverseOutputMemberMessage{Value: types.Message{
				Role: types.ConversationRoleAssistant,
				Content: []types.ContentBlock{
					&types.ContentBlockMemberToolUse{Value: types.ToolUseBlock{
						Name: aws.String("restart_service"), ToolUseId: aws.String("tool-1"),
						Input: document.NewLazyDocument(map[string]any{"reason": "health endpoint is failing"}),
					}},
				},
			}},
		},
		{
			Output: &types.ConverseOutputMemberMessage{Value: types.Message{
				Role: types.ConversationRoleAssistant,
				Content: []types.ContentBlock{
					&types.ContentBlockMemberText{Value: `{"summary":"service unhealthy","rationale":"health check failed","actions":[]}`},
				},
			}},
		},
	}}
	planner := NewBedrock(client, "model", 4096)
	plan, err := planner.Plan(t.Context(), model.Incident{AlarmName: "alarm", HostID: "host"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(client.inputs) != 2 || client.inputs[0].ToolConfig == nil || client.inputs[1].ToolConfig != nil {
		t.Fatalf("Converse calls were not a bounded tool loop")
	}
	if len(plan.Actions) != 1 || plan.Actions[0].OperationID != "restart_service" {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestBedrockRejectsActionWithoutToolSelection(t *testing.T) {
	client := &fakeConverse{outputs: []*bedrockruntime.ConverseOutput{{
		Output: &types.ConverseOutputMemberMessage{Value: types.Message{
			Role: types.ConversationRoleAssistant,
			Content: []types.ContentBlock{
				&types.ContentBlockMemberText{Value: `{"summary":"restart","rationale":"failed","actions":[{"operationId":"restart_service","reason":"failed"}]}`},
			},
		}},
	}}}
	planner := NewBedrock(client, "model", 4096)
	if _, err := planner.Plan(t.Context(), model.Incident{AlarmName: "alarm", HostID: "host"}, nil); err == nil {
		t.Fatal("Plan accepted an action without a tool request")
	}
}
