.PHONY: generate build test up down

generate:
	cd bpf && go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" \
		-target amd64 tcpprobes ./tcp_probes.c -- -I./headers

build: generate
	go build -o agent/bin/netmon ./agent

test:
	go test ./... -v

up:
	docker compose -f deploy/docker-compose.yml up -d

down:
	docker compose -f deploy/docker-compose.yml down
