package observability

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"
)

type contextKey string

const requestIDKey contextKey = "requestId"

func ConfigureLogger(service string) {
	env := os.Getenv("ENV")
	if env == "" {
		env = os.Getenv("DDM_ENV")
	}
	if env == "" {
		env = "dev"
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}).WithAttrs([]slog.Attr{
		slog.String("service", service),
		slog.String("env", env),
	})
	slog.SetDefault(slog.New(handler))
}

func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

func ContextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

func SetRequestHeaders(ctx context.Context, req *http.Request) {
	if requestID := RequestID(ctx); requestID != "" {
		req.Header.Set("X-Request-ID", requestID)
	}
}

func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(ContextWithRequestID(r.Context(), requestID)))
	})
}

func LogRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		slog.InfoContext(r.Context(), "http_request",
			"requestId", RequestID(r.Context()),
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"durationMs", time.Since(start).Milliseconds(),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

type Metric struct {
	Name  string
	Unit  string
	Value float64
}

func EmitMetric(service string, metrics []Metric, dimensions map[string]string) {
	if len(metrics) == 0 {
		return
	}
	env := os.Getenv("ENV")
	if env == "" {
		env = os.Getenv("DDM_ENV")
	}
	if env == "" {
		env = "dev"
	}
	values := map[string]any{"Service": service, "Environment": env}
	for key, value := range dimensions {
		if value != "" {
			values[key] = value
		}
	}
	definitions := make([]map[string]string, 0, len(metrics))
	for _, metric := range metrics {
		unit := metric.Unit
		if unit == "" {
			unit = "Count"
		}
		values[metric.Name] = metric.Value
		definitions = append(definitions, map[string]string{"Name": metric.Name, "Unit": unit})
	}
	values["_aws"] = map[string]any{
		"Timestamp": time.Now().UnixMilli(),
		"CloudWatchMetrics": []map[string]any{{
			"Namespace":  namespace(),
			"Dimensions": [][]string{{"Service", "Environment"}},
			"Metrics":    definitions,
		}},
	}
	if encoded, err := json.Marshal(values); err == nil {
		_, _ = os.Stdout.Write(append(encoded, '\n'))
	}
}

func EmitCount(service, name string, dimensions map[string]string) {
	EmitMetric(service, []Metric{{Name: name, Unit: "Count", Value: 1}}, dimensions)
}

func ErrorKind(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return "error"
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b[:])
}

func namespace() string {
	if value := os.Getenv("CLOUDWATCH_NAMESPACE"); value != "" {
		return value
	}
	return "DenDenMushi"
}
