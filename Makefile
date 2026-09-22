.PHONY: generate build test up down

generate:
	go generate ./bpf/...

build: generate
	go build -o agent/bin/netmon ./agent

test:
	go test ./... -v

up:
	docker compose -f deploy/docker-compose.yml up -d

down:
	docker compose -f deploy/docker-compose.yml down
