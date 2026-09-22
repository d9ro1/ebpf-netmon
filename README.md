# ebpf-netmon

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

    sudo apt-get update && sudo apt-get install -y clang llvm libbpf-dev linux-tools-common linux-tools-generic
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

    make test                                    # unit tests (no kernel needed)
    ./test/integration/run_integration_test.sh   # integration test (needs root, Linux)

## Status

Code for the full MVP (eBPF probes, Go agent, Prometheus/Grafana stack) is
written and committed, but has **not been compiled or run** on this
machine: neither Go, clang, nor a working WSL2 install were present at
write time. Before trusting this as working software, follow "First-time
setup" and "Build & run" above and confirm `make test`, `make build`, and
the integration test all pass.

## Scope

TCP/IPv4 only, single host, no alerting — see
`docs/superpowers/specs/2026-09-22-ebpf-netmon-design.md` for the full design
and explicit non-goals.
