.PHONY: test build run

test:
	go test ./...

build:
	go build ./cmd/server

run:
	go run ./cmd/server
