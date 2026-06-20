FROM golang:1.26.4-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/incident-agent ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/incident-agent /incident-agent
USER nonroot:nonroot
ENTRYPOINT ["/incident-agent"]
