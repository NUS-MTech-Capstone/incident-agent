package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/NUS-MTech-Capstone/incident-agent/internal/config"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/consumer"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/ddm"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/httpapi"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/observability"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/planner"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/service"
	"github.com/NUS-MTech-Capstone/incident-agent/internal/store"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

func main() {
	observability.ConfigureLogger("incident-agent")
	cfg := config.Load()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.AWSRegion))
	if err != nil {
		slog.Error("load AWS configuration failed", "error", err)
		return
	}
	databaseURL := cfg.DatabaseURL
	if databaseURL == "" && cfg.DatabaseSecretID != "" {
		output, err := secretsmanager.NewFromConfig(awsCfg).GetSecretValue(ctx,
			&secretsmanager.GetSecretValueInput{SecretId: &cfg.DatabaseSecretID})
		if err != nil {
			slog.Error("read database secret failed", "error", err)
			return
		}
		if output.SecretString != nil {
			databaseURL = strings.TrimSpace(*output.SecretString)
		}
	}
	if databaseURL == "" {
		slog.Error("DATABASE_URL or DATABASE_SECRET_ID is required")
		return
	}
	incidentStore, err := store.NewPostgres(ctx, databaseURL)
	if err != nil {
		slog.Error("initialize incident store failed", "error", err)
		return
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
	slog.Info("server_listening", "addr", ":"+cfg.Port, "model", cfg.BedrockModelID)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server failed", "error", err)
	}
}
