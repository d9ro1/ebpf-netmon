package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" -target amd64 -type conn_key -type conn_stats tcpprobes tcp_probes.c -- -I./headers
