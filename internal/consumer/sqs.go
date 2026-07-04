package consumer

import (
	"context"
	"log/slog"
	"time"

	"github.com/NUS-MTech-Capstone/incident-agent/internal/alerts"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/model"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/observability"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

type Handler interface {
	HandleAlert(context.Context, model.Alert) error
}

type SQS struct {
	client            *sqs.Client
	queueURL          string
	handler           Handler
	waitSeconds       int32
	visibilityTimeout int32
}

func NewSQS(client *sqs.Client, queueURL string, handler Handler, waitSeconds, visibilityTimeout int32) *SQS {
	return &SQS{
		client: client, queueURL: queueURL, handler: handler,
		waitSeconds: waitSeconds, visibilityTimeout: visibilityTimeout,
	}
}

func (c *SQS) Run(ctx context.Context) {
	if c.queueURL == "" {
		slog.Info("IncidentSQSConsumerDisabled")
		return
	}
	for ctx.Err() == nil {
		output, err := c.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
			QueueUrl: aws.String(c.queueURL), MaxNumberOfMessages: 10,
			WaitTimeSeconds: c.waitSeconds, VisibilityTimeout: c.visibilityTimeout,
		})
		if err != nil {
			if ctx.Err() == nil {
				slog.WarnContext(ctx, "IncidentAlertReceiveFailed",
					"errorKind", observability.ErrorKind(err),
					"error", err,
				)
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Second):
				}
			}
			continue
		}
		for _, message := range output.Messages {
			if message.Body == nil || message.ReceiptHandle == nil {
				continue
			}
			messageCtx := ctx
			if message.MessageId != nil {
				messageCtx = observability.ContextWithRequestID(ctx, *message.MessageId)
			}
			alert, err := alerts.ParseSQSBody(*message.Body)
			if err == nil {
				err = c.handler.HandleAlert(messageCtx, alert)
			}
			if err != nil {
				slog.WarnContext(messageCtx, "IncidentAlertHandlingFailed",
					"requestId", observability.RequestID(messageCtx),
					"alarmName", alert.AlarmName,
					"hostId", alert.HostID,
					"errorKind", observability.ErrorKind(err),
					"error", err,
				)
				continue
			}
			if _, err := c.client.DeleteMessage(ctx, &sqs.DeleteMessageInput{
				QueueUrl: aws.String(c.queueURL), ReceiptHandle: message.ReceiptHandle,
			}); err != nil {
				slog.WarnContext(messageCtx, "IncidentAlertDeleteFailed",
					"requestId", observability.RequestID(messageCtx),
					"errorKind", observability.ErrorKind(err),
					"error", err,
				)
			}
		}
	}
}
