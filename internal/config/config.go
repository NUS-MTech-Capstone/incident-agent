package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port                 string
	AWSRegion            string
	QueueURL             string
	DatabaseURL          string
	DatabaseSecretID     string
	ControlPlaneURL      string
	WorkloadTokenFile    string
	BedrockModelID       string
	BedrockMaxPrompt     int
	HTTPTimeout          time.Duration
	OperationTimeout     time.Duration
	MaxOperationOutput   int
	SQSPollWait          int32
	SQSVisibilityTimeout int32
}

func Load() Config {
	return Config{
		Port:                 env("PORT", "8091"),
		AWSRegion:            env("AWS_REGION", "ap-southeast-1"),
		QueueURL:             os.Getenv("INCIDENT_QUEUE_URL"),
		DatabaseURL:          os.Getenv("DATABASE_URL"),
		DatabaseSecretID:     os.Getenv("DATABASE_SECRET_ID"),
		ControlPlaneURL:      env("PROXY_CONTROLPLANE_URL", "http://localhost:8080"),
		WorkloadTokenFile:    env("WORKLOAD_TOKEN_FILE", "/var/run/secrets/tokens/incident-agent-token"),
		BedrockModelID:       env("BEDROCK_MODEL_ID", "global.amazon.nova-2-lite-v1:0"),
		BedrockMaxPrompt:     intEnv("BEDROCK_MAX_PROMPT_BYTES", 128*1024),
		HTTPTimeout:          durationEnv("HTTP_TIMEOUT", 10*time.Second),
		OperationTimeout:     durationEnv("OPERATION_TIMEOUT", 45*time.Second),
		MaxOperationOutput:   intEnv("MAX_OPERATION_OUTPUT_BYTES", 256*1024),
		SQSPollWait:          int32(intEnv("SQS_POLL_WAIT_SECONDS", 20)),
		SQSVisibilityTimeout: int32(intEnv("SQS_VISIBILITY_TIMEOUT_SECONDS", 600)),
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func intEnv(key string, fallback int) int {
	value, err := strconv.Atoi(env(key, strconv.Itoa(fallback)))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(env(key, fallback.String()))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
