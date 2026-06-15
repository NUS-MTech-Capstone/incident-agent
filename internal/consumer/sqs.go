package consumer

import (
	"context"
	"log"
	"time"

	"github.com/NUS-MTech-Capstone/incident-agent/internal/alerts"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/model"
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
		log.Printf("incident SQS consumer disabled: INCIDENT_QUEUE_URL is empty")
		return
	}
	for ctx.Err() == nil {
		output, err := c.client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
			QueueUrl: aws.String(c.queueURL), MaxNumberOfMessages: 10,
			WaitTimeSeconds: c.waitSeconds, VisibilityTimeout: c.visibilityTimeout,
		})
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("receive incident alerts failed: %v", err)
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
			alert, err := alerts.ParseSQSBody(*message.Body)
			if err == nil {
				err = c.handler.HandleAlert(ctx, alert)
			}
			if err != nil {
				log.Printf("incident alert handling failed: %v", err)
				continue
			}
			if _, err := c.client.DeleteMessage(ctx, &sqs.DeleteMessageInput{
				QueueUrl: aws.String(c.queueURL), ReceiptHandle: message.ReceiptHandle,
			}); err != nil {
				log.Printf("delete incident alert failed: %v", err)
			}
		}
	}
}
