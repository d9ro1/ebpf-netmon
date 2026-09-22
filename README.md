# ebpf-netmon

[![CI](https://github.com/d9ro1/ebpf-netmon/actions/workflows/ci.yml/badge.svg)](https://github.com/d9ro1/ebpf-netmon/actions/workflows/ci.yml)

Per-process TCP observability via eBPF: connection latency, retransmissions
and throughput, exported as Prometheus metrics and visualized in Grafana.

## Why

Most container-level network dashboards stop at "bytes in/out per pod".
This attaches directly to the Linux TCP stack (kprobes on `tcp_connect`,
`tcp_close`, `tcp_retransmit_skb`, `tcp_sendmsg`, `tcp_cleanup_rbuf`) to
attribute network behavior to the actual process, with no application-side
instrumentation required.

## Requirements

- Linux kernel >= 5.8 with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
- On Windows: WSL2. If `wsl --status` fails or `wsl.exe` errors with
  `REGDB_E_CLASSNOTREG` (as it currently does on this machine), WSL is not
  installed — run, as Administrator:

      wsl --install

  then reboot. If it still fails, enable manually via
  `Optional Features > Windows Subsystem for Linux` and
  `Virtual Machine Platform`, then reboot and retry `wsl --install`.
- Inside WSL2: `clang`, `llvm`, `libbpf-dev`, `linux-tools-generic`, Go 1.22+,
  Docker (or Docker Desktop with WSL2 integration enabled).

## First-time setup (inside WSL2)

    sudo apt-get update && sudo apt-get install -y clang llvm libbpf-dev

    # Install bpftool from the upstream static release, not apt: the apt
    # package is a wrapper tied to an exact linux-tools-<kernel-version>
    # package that frequently doesn't exist for your exact kernel build.
    URL=$(curl -s https://api.github.com/repos/libbpf/bpftool/releases/latest \
      | grep browser_download_url | grep -i 'amd64\.tar\.gz' | head -1 | cut -d '"' -f4)
    curl -sL "$URL" -o bpftool.tar.gz && tar -xzf bpftool.tar.gz
    sudo install -m 0755 bpftool /usr/local/bin/bpftool

    mkdir -p bpf/headers/bpf
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
    cp /usr/include/bpf/*.h bpf/headers/bpf/
    go mod tidy   # fetches cilium/ebpf and client_golang, generates go.sum

## Build & run

    make generate   # regenerate Go bindings from bpf/tcp_probes.c
    make build       # produces agent/bin/netmon
    sudo ./agent/bin/netmon   # root/CAP_BPF required to load eBPF programs

## Observability stack

    make up   # starts Prometheus (:9090) and Grafana (:3000, admin/admin)

The `netmon` dashboard is provisioned automatically in Grafana.

## Testing

    make test                                     # unit tests (no kernel needed)
    bash ./test/integration/run_integration_test.sh   # integration test (needs root, Linux)

## Status

Verified working end-to-end by CI (see badge above): every push builds the
BPF probes, builds the Go agent, runs the unit tests, and runs the
integration test (loads the real kprobes on the runner's kernel, generates
known TCP traffic, and checks the resulting Prometheus metrics).

This was built and debugged entirely through that CI loop: the dev machine
this was written on has no Go, clang, or working WSL2 install, so local
compilation was never possible here. If you're setting it up locally
(inside WSL2 or any Linux box), follow "First-time setup" and "Build & run"
above — CI passing is strong evidence it'll work, but it's not a substitute
for running it yourself once.

## Scope

TCP/IPv4 only, single host, no alerting — see
`docs/superpowers/specs/2026-09-22-ebpf-netmon-design.md` for the full design
and explicit non-goals.
