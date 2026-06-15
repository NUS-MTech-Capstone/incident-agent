package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/NUS-MTech-Capstone/incident-agent/internal/config"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/consumer"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/ddm"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/httpapi"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/planner"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/service"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/store"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

func main() {
	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWSRegion))
	if err != nil {
		log.Fatalf("load AWS configuration: %v", err)
	}
	databaseURL := cfg.DatabaseURL
	if databaseURL == "" && cfg.DatabaseSecretID != "" {
		output, err := secretsmanager.NewFromConfig(awsCfg).GetSecretValue(ctx,
			&secretsmanager.GetSecretValueInput{SecretId: &cfg.DatabaseSecretID})
		if err != nil {
			log.Fatalf("read database secret: %v", err)
		}
		if output.SecretString != nil {
			databaseURL = strings.TrimSpace(*output.SecretString)
		}
	}
	if databaseURL == "" {
		log.Fatal("DATABASE_URL or DATABASE_SECRET_ID is required")
	}
	incidentStore, err := store.NewPostgres(ctx, databaseURL)
	if err != nil {
		log.Fatalf("initialize incident store: %v", err)
	}
	defer incidentStore.Close()
	ddmClient := ddm.New(cfg.ControlPlaneURL, cfg.WorkloadTokenFile, cfg.HTTPTimeout)
	bedrockPlanner := planner.NewBedrock(
		bedrockruntime.NewFromConfig(awsCfg), cfg.BedrockModelID, cfg.BedrockMaxPrompt,
	)
	svc := service.New(incidentStore, bedrockPlanner, ddmClient, cfg.OperationTimeout, cfg.MaxOperationOutput)
	sqsConsumer := consumer.NewSQS(
		sqs.NewFromConfig(awsCfg), cfg.QueueURL, svc, cfg.SQSPollWait, cfg.SQSVisibilityTimeout,
	)
	go sqsConsumer.Run(ctx)

	server := &http.Server{
		Addr: ":" + cfg.Port, Handler: httpapi.New(svc),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("incident-agent listening on :%s model=%s", cfg.Port, cfg.BedrockModelID)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
