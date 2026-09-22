# ebpf-netmon Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Go agent that loads eBPF kprobes on the Linux TCP stack to
measure per-process connection latency, retransmissions and throughput, and
exposes them as Prometheus metrics visualized in Grafana.

**Architecture:** eBPF C programs (kprobes on `tcp_connect`, `tcp_close`,
`tcp_retransmit_skb`, `tcp_sendmsg`, `tcp_recvmsg`) write per-PID counters
into BPF hash maps. A Go userspace agent (using `cilium/ebpf` + `bpf2go`)
polls these maps every 5s, resolves PIDs to process names, resets the
counters it read, and serves the aggregates on `/metrics`. Prometheus
scrapes the agent; Grafana visualizes it.

**Tech Stack:** Go 1.22+, `github.com/cilium/ebpf` (+ `bpf2go`), clang/LLVM
for BPF C compilation, `github.com/prometheus/client_golang`, Docker Compose,
Prometheus, Grafana. Runs on Linux (kernel ≥ 5.8) — via WSL2 on the dev
machine.

**Spec:** `docs/superpowers/specs/2026-09-22-ebpf-netmon-design.md`

## Global Constraints

- IPv4 only, TCP only (no UDP, no IPv6) — MVP scope per spec.
- No crash on a single probe failing to attach — log and continue with the
  rest.
- No crash on `/proc/<pid>/comm` missing — label as `unknown (pid <N>)`.
- Single host only — no multi-host aggregation.
- Counters are reset after each read (delta-per-interval semantics), not
  cumulative counters.

---

### Task 1: Project scaffolding

**Files:**
- Create: `go.mod`, `go.sum` (generated)
- Create: `.gitignore`
- Create: `Makefile`

**Interfaces:**
- Produces: `Makefile` targets `generate`, `build`, `test`, `up`, `down`
  that every later task's instructions reference.

- [ ] **Step 1: Initialize the Go module**

```bash
cd /c/Users/yarra/projects/ebpf-netmon
go mod init github.com/yarra/ebpf-netmon
```

- [ ] **Step 2: Add `.gitignore`**

```
/agent/bin/
*.o
/deploy/grafana/data/
/deploy/prometheus/data/
```

- [ ] **Step 3: Add the `Makefile`**

```makefile
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
```

- [ ] **Step 4: Commit**

```bash
git add go.mod .gitignore Makefile
git commit -m "chore: scaffold Go module and Makefile"
```

---

### Task 2: eBPF C programs (kprobes + maps)

**Files:**
- Create: `bpf/tcp_probes.c`
- Create: `bpf/gen.go`

**Interfaces:**
- Produces: BPF maps `conn_stats` (key `struct conn_key`, value
  `struct conn_stats`) and `pid_by_sock` (key `u64` sock pointer, value `u32`
  pid) — consumed by Task 6's `bpfreader` adapter via the generated `bpf2go`
  Go types `bpf.TcpprobesConnKey`, `bpf.TcpprobesConnStats`, and map objects
  `bpf.TcpprobesObjects.ConnStats` / `bpf.TcpprobesObjects.PidBySock`.

- [ ] **Step 1: Write the BPF program**

```c
// bpf/tcp_probes.c
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct conn_key {
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct conn_stats {
    __u64 bytes_sent;
    __u64 bytes_recv;
    __u64 retransmits;
    __u64 connect_latency_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct conn_key);
    __type(value, struct conn_stats);
} conn_stats SEC(".maps");

// Maps a live `struct sock *` to the PID that owns it, set at connect time
// and read by sendmsg/recvmsg/retransmit probes that only get the sock.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u32);
} pid_by_sock SEC(".maps");

// Connect start timestamps, keyed by sock pointer, to compute latency at
// tcp_close time (tcp_connect fires before the handshake completes).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u64);
} connect_start SEC(".maps");

static __always_inline void fill_key_from_sock(struct conn_key *key, struct sock *sk, __u32 pid) {
    key->pid = pid;
    key->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_tcp_connect, struct sock *sk) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 sock_ptr = (__u64)sk;
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&pid_by_sock, &sock_ptr, &pid, BPF_ANY);
    bpf_map_update_elem(&connect_start, &sock_ptr, &ts, BPF_ANY);
    return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(trace_tcp_close, struct sock *sk) {
    __u64 sock_ptr = (__u64)sk;
    __u32 *pid = bpf_map_lookup_elem(&pid_by_sock, &sock_ptr);
    __u64 *start_ts = bpf_map_lookup_elem(&connect_start, &sock_ptr);
    if (!pid)
        return 0;

    struct conn_key key = {};
    fill_key_from_sock(&key, sk, *pid);

    struct conn_stats *stats = bpf_map_lookup_elem(&conn_stats, &key);
    if (stats && start_ts) {
        stats->connect_latency_ns = bpf_ktime_get_ns() - *start_ts;
    }

    bpf_map_delete_elem(&pid_by_sock, &sock_ptr);
    bpf_map_delete_elem(&connect_start, &sock_ptr);
    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(trace_tcp_retransmit_skb, struct sock *sk) {
    __u64 sock_ptr = (__u64)sk;
    __u32 *pid = bpf_map_lookup_elem(&pid_by_sock, &sock_ptr);
    if (!pid)
        return 0;

    struct conn_key key = {};
    fill_key_from_sock(&key, sk, *pid);

    struct conn_stats zero = {};
    struct conn_stats *stats = bpf_map_lookup_elem(&conn_stats, &key);
    if (!stats) {
        bpf_map_update_elem(&conn_stats, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&conn_stats, &key);
        if (!stats)
            return 0;
    }
    __sync_fetch_and_add(&stats->retransmits, 1);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    __u64 sock_ptr = (__u64)sk;
    __u32 *pid = bpf_map_lookup_elem(&pid_by_sock, &sock_ptr);
    if (!pid)
        return 0;

    struct conn_key key = {};
    fill_key_from_sock(&key, sk, *pid);

    struct conn_stats zero = {};
    struct conn_stats *stats = bpf_map_lookup_elem(&conn_stats, &key);
    if (!stats) {
        bpf_map_update_elem(&conn_stats, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&conn_stats, &key);
        if (!stats)
            return 0;
    }
    __sync_fetch_and_add(&stats->bytes_sent, size);
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(trace_tcp_recvmsg, struct sock *sk, int copied) {
    if (copied <= 0)
        return 0;

    __u64 sock_ptr = (__u64)sk;
    __u32 *pid = bpf_map_lookup_elem(&pid_by_sock, &sock_ptr);
    if (!pid)
        return 0;

    struct conn_key key = {};
    fill_key_from_sock(&key, sk, *pid);

    struct conn_stats zero = {};
    struct conn_stats *stats = bpf_map_lookup_elem(&conn_stats, &key);
    if (!stats) {
        bpf_map_update_elem(&conn_stats, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&conn_stats, &key);
        if (!stats)
            return 0;
    }
    __sync_fetch_and_add(&stats->bytes_recv, copied);
    return 0;
}
```

Note: `tcp_recvmsg` doesn't carry a reliable byte count on entry across
kernel versions, so throughput-in is measured via `tcp_cleanup_rbuf(sk,
copied)`, which reports bytes actually copied to userspace — this is the
approach used by BCC's `tcplife`/`tcptop` tools for the same reason.

- [ ] **Step 2: Add the `go:generate` directive**

```go
// bpf/gen.go
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" -target amd64 tcpprobes tcp_probes.c -- -I./headers
```

- [ ] **Step 3: Fetch `vmlinux.h` and libbpf headers (run under WSL2)**

```bash
sudo apt-get update && sudo apt-get install -y clang llvm libbpf-dev linux-tools-common linux-tools-generic
mkdir -p bpf/headers/bpf
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
cp /usr/include/bpf/bpf_helpers.h /usr/include/bpf/bpf_tracing.h bpf/headers/bpf/
```

Expected: `bpf/vmlinux.h` exists and is non-empty; `bpf/headers/bpf/` contains
the two header files.

- [ ] **Step 4: Generate the Go bindings and verify the build**

```bash
make generate
```

Expected: `bpf/tcpprobes_bpfel_x86.go` and `bpf/tcpprobes_bpfel_x86.o` are
created, no compiler errors.

- [ ] **Step 5: Commit**

```bash
git add bpf/tcp_probes.c bpf/gen.go bpf/vmlinux.h bpf/headers .gitignore
git commit -m "feat: add eBPF TCP kprobes and BPF maps"
```

---

### Task 3: `procresolve` package (PID → process name)

**Files:**
- Create: `agent/procresolve/procresolve.go`
- Test: `agent/procresolve/procresolve_test.go`

**Interfaces:**
- Produces: `type Resolver struct{}`, `func NewResolver() *Resolver`,
  `func (r *Resolver) Resolve(pid uint32) string` — returns the process
  `comm` name, or `"unknown (pid <N>)"` if the process is gone. Consumed by
  Task 5's `metrics` updater.

- [ ] **Step 1: Write the failing test**

```go
// agent/procresolve/procresolve_test.go
package procresolve

import (
	"os"
	"strconv"
	"testing"
)

func TestResolve_CurrentProcess(t *testing.T) {
	r := NewResolver()
	pid := uint32(os.Getpid())
	name := r.Resolve(pid)
	if name == "" || name == unknownLabel(pid) {
		t.Fatalf("expected a real process name for our own pid, got %q", name)
	}
}

func TestResolve_UnknownPid(t *testing.T) {
	r := NewResolver()
	// Extremely unlikely to be a real running pid.
	const fakePid = uint32(4_000_000)
	name := r.Resolve(fakePid)
	want := "unknown (pid " + strconv.FormatUint(uint64(fakePid), 10) + ")"
	if name != want {
		t.Fatalf("got %q, want %q", name, want)
	}
}

func TestResolve_CachesResult(t *testing.T) {
	r := NewResolver()
	pid := uint32(os.Getpid())
	first := r.Resolve(pid)
	second := r.Resolve(pid)
	if first != second {
		t.Fatalf("expected cached result to match: %q vs %q", first, second)
	}
	if _, cached := r.cache[pid]; !cached {
		t.Fatalf("expected pid %d to be cached after Resolve", pid)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./agent/procresolve/... -v`
Expected: FAIL — `NewResolver` / `Resolve` undefined.

- [ ] **Step 3: Write the implementation**

```go
// agent/procresolve/procresolve.go
package procresolve

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

// Resolver resolves PIDs to process names, caching results since a PID's
// comm doesn't change for the life of the process.
type Resolver struct {
	mu    sync.Mutex
	cache map[uint32]string
}

func NewResolver() *Resolver {
	return &Resolver{cache: make(map[uint32]string)}
}

func unknownLabel(pid uint32) string {
	return fmt.Sprintf("unknown (pid %d)", pid)
}

// Resolve returns the process name for pid, or an "unknown (pid N)" label
// if /proc/<pid>/comm cannot be read (the process has already exited).
func (r *Resolver) Resolve(pid uint32) string {
	r.mu.Lock()
	if name, ok := r.cache[pid]; ok {
		r.mu.Unlock()
		return name
	}
	r.mu.Unlock()

	name := r.readComm(pid)
	r.mu.Lock()
	r.cache[pid] = name
	r.mu.Unlock()
	return name
}

func (r *Resolver) readComm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return unknownLabel(pid)
	}
	return strings.TrimSpace(string(data))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./agent/procresolve/... -v`
Expected: PASS (all 3 tests)

- [ ] **Step 5: Commit**

```bash
git add agent/procresolve
git commit -m "feat: add PID to process name resolver with caching"
```

---

### Task 4: `collector` package (BPF map polling + aggregation)

**Files:**
- Create: `agent/collector/collector.go`
- Test: `agent/collector/collector_test.go`

**Interfaces:**
- Consumes: `procresolve.Resolver.Resolve(pid uint32) string` from Task 3.
- Produces: `type MapReader interface { Iterate() ([]Entry, error); Delete(key ConnKey) error }`,
  `type ConnKey struct{ PID uint32; SAddr, DAddr uint32; SPort, DPort uint16 }`,
  `type ConnStats struct{ BytesSent, BytesRecv, Retransmits, ConnectLatencyNs uint64 }`,
  `type Entry struct{ Key ConnKey; Stats ConnStats }`,
  `type Aggregate struct{ Process string; BytesSent, BytesRecv, Retransmits uint64; ConnectLatencyNs uint64 }`,
  `type Collector struct{...}`, `func NewCollector(reader MapReader, resolver *procresolve.Resolver) *Collector`,
  `func (c *Collector) Collect() ([]Aggregate, error)` — consumed by Task 5's
  metrics updater and Task 6's `main.go`. `Collect` reads all entries, groups
  by resolved process name, sums stats, deletes every read entry from the
  underlying map (delta semantics), and never returns an error solely
  because deletion failed for one entry (logs and continues, per the
  spec's "no crash on map errors" constraint).

- [ ] **Step 1: Write the failing test**

```go
// agent/collector/collector_test.go
package collector

import (
	"errors"
	"testing"

	"github.com/yarra/ebpf-netmon/agent/procresolve"
)

type fakeReader struct {
	entries []Entry
	deleted []ConnKey
	failNth int // if > 0, Delete fails for that many calls (1-indexed)
	calls   int
}

func (f *fakeReader) Iterate() ([]Entry, error) {
	return f.entries, nil
}

func (f *fakeReader) Delete(key ConnKey) error {
	f.calls++
	if f.failNth > 0 && f.calls == f.failNth {
		return errors.New("simulated delete failure")
	}
	f.deleted = append(f.deleted, key)
	return nil
}

func TestCollect_AggregatesByProcess(t *testing.T) {
	reader := &fakeReader{
		entries: []Entry{
			{Key: ConnKey{PID: 100}, Stats: ConnStats{BytesSent: 10, BytesRecv: 5}},
			{Key: ConnKey{PID: 100, DPort: 443}, Stats: ConnStats{BytesSent: 20, Retransmits: 1}},
			{Key: ConnKey{PID: 200}, Stats: ConnStats{BytesRecv: 7}},
		},
	}
	resolver := procresolve.NewResolver()

	c := NewCollector(reader, resolver)
	aggs, err := c.Collect()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(aggs) != 2 {
		t.Fatalf("expected 2 aggregates (2 distinct pids), got %d", len(aggs))
	}

	var pid100Sent, pid100Retrans uint64
	for _, a := range aggs {
		if a.BytesSent == 30 {
			pid100Sent = a.BytesSent
			pid100Retrans = a.Retransmits
		}
	}
	if pid100Sent != 30 || pid100Retrans != 1 {
		t.Fatalf("expected pid 100 aggregate BytesSent=30 Retransmits=1, got sent=%d retrans=%d", pid100Sent, pid100Retrans)
	}
}

func TestCollect_DeletesReadEntries(t *testing.T) {
	reader := &fakeReader{
		entries: []Entry{{Key: ConnKey{PID: 1}, Stats: ConnStats{BytesSent: 1}}},
	}
	c := NewCollector(reader, procresolve.NewResolver())
	if _, err := c.Collect(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reader.deleted) != 1 {
		t.Fatalf("expected 1 deleted entry, got %d", len(reader.deleted))
	}
}

func TestCollect_ContinuesOnDeleteError(t *testing.T) {
	reader := &fakeReader{
		entries: []Entry{
			{Key: ConnKey{PID: 1}, Stats: ConnStats{BytesSent: 1}},
			{Key: ConnKey{PID: 2}, Stats: ConnStats{BytesSent: 2}},
		},
		failNth: 1,
	}
	c := NewCollector(reader, procresolve.NewResolver())
	aggs, err := c.Collect()
	if err != nil {
		t.Fatalf("expected no error even when one delete fails, got %v", err)
	}
	if len(aggs) != 2 {
		t.Fatalf("expected both aggregates despite one delete failure, got %d", len(aggs))
	}
	if len(reader.deleted) != 1 {
		t.Fatalf("expected exactly 1 successful delete, got %d", len(reader.deleted))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./agent/collector/... -v`
Expected: FAIL — package/types undefined.

- [ ] **Step 3: Write the implementation**

```go
// agent/collector/collector.go
package collector

import (
	"log"

	"github.com/yarra/ebpf-netmon/agent/procresolve"
)

type ConnKey struct {
	PID              uint32
	SAddr, DAddr     uint32
	SPort, DPort     uint16
}

type ConnStats struct {
	BytesSent, BytesRecv, Retransmits, ConnectLatencyNs uint64
}

type Entry struct {
	Key   ConnKey
	Stats ConnStats
}

// MapReader abstracts reading and clearing the BPF conn_stats map so the
// collector's aggregation logic can be tested without a real kernel.
type MapReader interface {
	Iterate() ([]Entry, error)
	Delete(key ConnKey) error
}

type Aggregate struct {
	Process          string
	BytesSent        uint64
	BytesRecv        uint64
	Retransmits      uint64
	ConnectLatencyNs uint64
}

type Collector struct {
	reader   MapReader
	resolver *procresolve.Resolver
}

func NewCollector(reader MapReader, resolver *procresolve.Resolver) *Collector {
	return &Collector{reader: reader, resolver: resolver}
}

// Collect reads every entry currently in the map, aggregates the stats by
// resolved process name, deletes each entry it read (delta-per-interval
// semantics), and returns the aggregates. A failure to delete one entry is
// logged and does not fail the collection.
func (c *Collector) Collect() ([]Aggregate, error) {
	entries, err := c.reader.Iterate()
	if err != nil {
		return nil, err
	}

	byProcess := make(map[string]*Aggregate)
	for _, e := range entries {
		name := c.resolver.Resolve(e.Key.PID)
		agg, ok := byProcess[name]
		if !ok {
			agg = &Aggregate{Process: name}
			byProcess[name] = agg
		}
		agg.BytesSent += e.Stats.BytesSent
		agg.BytesRecv += e.Stats.BytesRecv
		agg.Retransmits += e.Stats.Retransmits
		if e.Stats.ConnectLatencyNs > agg.ConnectLatencyNs {
			agg.ConnectLatencyNs = e.Stats.ConnectLatencyNs
		}

		if delErr := c.reader.Delete(e.Key); delErr != nil {
			log.Printf("collector: failed to delete map entry for pid %d: %v", e.Key.PID, delErr)
		}
	}

	result := make([]Aggregate, 0, len(byProcess))
	for _, agg := range byProcess {
		result = append(result, *agg)
	}
	return result, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./agent/collector/... -v`
Expected: PASS (all 3 tests)

- [ ] **Step 5: Commit**

```bash
git add agent/collector
git commit -m "feat: add collector that aggregates BPF map entries by process"
```

---

### Task 5: `metrics` package (Prometheus export)

**Files:**
- Create: `agent/metrics/metrics.go`
- Test: `agent/metrics/metrics_test.go`
- Modify: `go.mod` (add `github.com/prometheus/client_golang` dependency)

**Interfaces:**
- Consumes: `collector.Aggregate` from Task 4.
- Produces: `type Metrics struct{}`, `func NewMetrics() *Metrics`,
  `func (m *Metrics) Update(aggs []collector.Aggregate)`,
  `func (m *Metrics) Handler() http.Handler` — consumed by Task 6's
  `main.go` to serve `/metrics`.

- [ ] **Step 1: Add the Prometheus client dependency**

```bash
go get github.com/prometheus/client_golang/prometheus
go get github.com/prometheus/client_golang/prometheus/promauto
go get github.com/prometheus/client_golang/prometheus/promhttp
```

- [ ] **Step 2: Write the failing test**

```go
// agent/metrics/metrics_test.go
package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yarra/ebpf-netmon/agent/collector"
)

func TestUpdate_ExposesBytesSentByProcess(t *testing.T) {
	m := NewMetrics()
	m.Update([]collector.Aggregate{
		{Process: "curl", BytesSent: 1024, BytesRecv: 2048, Retransmits: 1, ConnectLatencyNs: 1_500_000},
	})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `netmon_bytes_sent_total{process="curl"} 1024`) {
		t.Fatalf("expected bytes_sent metric for curl in output:\n%s", body)
	}
	if !strings.Contains(body, `netmon_retransmits_total{process="curl"} 1`) {
		t.Fatalf("expected retransmits metric for curl in output:\n%s", body)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./agent/metrics/... -v`
Expected: FAIL — package/types undefined.

- [ ] **Step 4: Write the implementation**

```go
// agent/metrics/metrics.go
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/yarra/ebpf-netmon/agent/collector"
)

type Metrics struct {
	bytesSent        *prometheus.CounterVec
	bytesRecv        *prometheus.CounterVec
	retransmits      *prometheus.CounterVec
	connectLatency   *prometheus.GaugeVec
	registry         *prometheus.Registry
}

func NewMetrics() *Metrics {
	registry := prometheus.NewRegistry()
	factory := promauto.With(registry)

	return &Metrics{
		registry: registry,
		bytesSent: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "netmon_bytes_sent_total",
			Help: "Total bytes sent over TCP, by process, since the last scrape interval.",
		}, []string{"process"}),
		bytesRecv: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "netmon_bytes_received_total",
			Help: "Total bytes received over TCP, by process, since the last scrape interval.",
		}, []string{"process"}),
		retransmits: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "netmon_retransmits_total",
			Help: "Total TCP retransmissions, by process, since the last scrape interval.",
		}, []string{"process"}),
		connectLatency: factory.NewGaugeVec(prometheus.GaugeOpts{
			Name: "netmon_connect_latency_seconds",
			Help: "Max observed TCP connect latency, by process, in the last scrape interval.",
		}, []string{"process"}),
	}
}

// Update adds each aggregate's counters to the running totals for its
// process label. Counters, not gauges, because the collector hands us
// per-interval deltas (it resets the underlying BPF map after each read).
func (m *Metrics) Update(aggs []collector.Aggregate) {
	for _, a := range aggs {
		m.bytesSent.WithLabelValues(a.Process).Add(float64(a.BytesSent))
		m.bytesRecv.WithLabelValues(a.Process).Add(float64(a.BytesRecv))
		m.retransmits.WithLabelValues(a.Process).Add(float64(a.Retransmits))
		m.connectLatency.WithLabelValues(a.Process).Set(float64(a.ConnectLatencyNs) / 1e9)
	}
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./agent/metrics/... -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add agent/metrics go.mod go.sum
git commit -m "feat: add Prometheus metrics export"
```

---

### Task 6: BPF-backed `MapReader` adapter and `main.go` wiring

**Files:**
- Create: `agent/bpfreader/bpfreader.go`
- Create: `agent/main.go`

**Interfaces:**
- Consumes: `bpf.tcpprobesObjects` (generated in Task 2), `collector.MapReader`
  interface, `collector.Entry`/`ConnKey`/`ConnStats` (Task 4), `metrics.Metrics`
  (Task 5), `procresolve.Resolver` (Task 3).
- Produces: `type BPFMapReader struct{}`,
  `func NewBPFMapReader(m *ebpf.Map) *BPFMapReader` implementing
  `collector.MapReader` — this is the only task that touches the real
  kernel map; it has no unit test (requires root + a loaded map) and is
  instead covered by Task 7's integration test.

- [ ] **Step 1: Write the BPF-backed map reader**

```go
// agent/bpfreader/bpfreader.go
package bpfreader

import (
	"github.com/cilium/ebpf"

	"github.com/yarra/ebpf-netmon/agent/collector"
	"github.com/yarra/ebpf-netmon/bpf"
)

// BPFMapReader adapts a real *ebpf.Map (the loaded conn_stats BPF map) to
// the collector.MapReader interface.
type BPFMapReader struct {
	m *ebpf.Map
}

func NewBPFMapReader(m *ebpf.Map) *BPFMapReader {
	return &BPFMapReader{m: m}
}

func (r *BPFMapReader) Iterate() ([]collector.Entry, error) {
	var (
		entries []collector.Entry
		key     bpf.TcpprobesConnKey
		val     bpf.TcpprobesConnStats
	)
	it := r.m.Iterate()
	for it.Next(&key, &val) {
		entries = append(entries, collector.Entry{
			Key: collector.ConnKey{
				PID: key.Pid, SAddr: key.Saddr, DAddr: key.Daddr,
				SPort: key.Sport, DPort: key.Dport,
			},
			Stats: collector.ConnStats{
				BytesSent: val.BytesSent, BytesRecv: val.BytesRecv,
				Retransmits: val.Retransmits, ConnectLatencyNs: val.ConnectLatencyNs,
			},
		})
	}
	return entries, it.Err()
}

func (r *BPFMapReader) Delete(key collector.ConnKey) error {
	bpfKey := bpf.TcpprobesConnKey{
		Pid: key.PID, Saddr: key.SAddr, Daddr: key.DAddr,
		Sport: key.SPort, Dport: key.DPort,
	}
	return r.m.Delete(&bpfKey)
}
```

- [ ] **Step 2: Write `main.go`**

```go
// agent/main.go
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/cilium/ebpf/link"

	"github.com/yarra/ebpf-netmon/agent/bpfreader"
	"github.com/yarra/ebpf-netmon/agent/collector"
	"github.com/yarra/ebpf-netmon/agent/metrics"
	"github.com/yarra/ebpf-netmon/agent/procresolve"
	"github.com/yarra/ebpf-netmon/bpf"
)

const pollInterval = 5 * time.Second

// probeSpecs maps each kprobe to the kernel symbol it attaches to. A probe
// that fails to attach (old kernel, missing symbol) is logged and skipped —
// the agent keeps running with whichever probes succeeded.
func attachProbes(objs *bpf.TcpprobesObjects) []link.Link {
	var links []link.Link
	type attempt struct {
		name   string
		symbol string
		attach func() (link.Link, error)
	}
	attempts := []attempt{
		{"tcp_connect", "tcp_connect", func() (link.Link, error) {
			return link.Kprobe("tcp_connect", objs.TraceTcpConnect, nil)
		}},
		{"tcp_close", "tcp_close", func() (link.Link, error) {
			return link.Kprobe("tcp_close", objs.TraceTcpClose, nil)
		}},
		{"tcp_retransmit_skb", "tcp_retransmit_skb", func() (link.Link, error) {
			return link.Kprobe("tcp_retransmit_skb", objs.TraceTcpRetransmitSkb, nil)
		}},
		{"tcp_sendmsg", "tcp_sendmsg", func() (link.Link, error) {
			return link.Kprobe("tcp_sendmsg", objs.TraceTcpSendmsg, nil)
		}},
		{"tcp_cleanup_rbuf", "tcp_cleanup_rbuf", func() (link.Link, error) {
			return link.Kprobe("tcp_cleanup_rbuf", objs.TraceTcpRecvmsg, nil)
		}},
	}

	for _, a := range attempts {
		l, err := a.attach()
		if err != nil {
			log.Printf("main: failed to attach probe %s (symbol %s): %v — continuing without it", a.name, a.symbol, err)
			continue
		}
		links = append(links, l)
	}
	return links
}

func main() {
	objs := bpf.TcpprobesObjects{}
	if err := bpf.LoadTcpprobesObjects(&objs, nil); err != nil {
		log.Fatalf("main: failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	links := attachProbes(&objs)
	if len(links) == 0 {
		log.Fatalf("main: no probes could be attached, exiting")
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	reader := bpfreader.NewBPFMapReader(objs.ConnStats)
	resolver := procresolve.NewResolver()
	coll := collector.NewCollector(reader, resolver)
	m := metrics.NewMetrics()

	go func() {
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()
		for range ticker.C {
			aggs, err := coll.Collect()
			if err != nil {
				log.Printf("main: collect failed: %v", err)
				continue
			}
			m.Update(aggs)
		}
	}()

	http.Handle("/metrics", m.Handler())
	log.Println("main: serving /metrics on :9200")
	log.Fatal(http.ListenAndServe(":9200", nil))
}
```

- [ ] **Step 3: Build to verify it compiles (run under WSL2, after Task 2's `make generate`)**

Run: `make build`
Expected: `agent/bin/netmon` binary produced, no compile errors.

- [ ] **Step 4: Commit**

```bash
git add agent/bpfreader agent/main.go
git commit -m "feat: wire BPF probes, collector and metrics into the agent binary"
```

---

### Task 7: Integration test script

**Files:**
- Create: `test/integration/run_integration_test.sh`
- Create: `test/integration/generate_traffic.py`

**Interfaces:**
- Consumes: `agent/bin/netmon` (built in Task 6), exposed `/metrics` on
  `:9200`.
- Produces: a pass/fail shell script other tasks don't depend on — this is
  the final verification step for the MVP.

- [ ] **Step 1: Write the traffic generator**

```python
# test/integration/generate_traffic.py
import http.server
import socketserver
import threading
import urllib.request

PORT = 8765


def serve():
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("127.0.0.1", PORT), handler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    for _ in range(20):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=2).read()
        except Exception as exc:
            print(f"request failed: {exc}")
    print("traffic generation done")
```

- [ ] **Step 2: Write the integration test script**

```bash
#!/usr/bin/env bash
# test/integration/run_integration_test.sh
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "Building agent..."
make build

echo "Starting agent (requires root for BPF)..."
sudo ./agent/bin/netmon &
AGENT_PID=$!
sleep 2

echo "Generating known TCP traffic..."
python3 test/integration/generate_traffic.py

sleep 6  # let one 5s collection interval pass

echo "Checking /metrics for our own process..."
METRICS=$(curl -s http://localhost:9200/metrics)
if echo "$METRICS" | grep -q 'netmon_bytes_sent_total{process="python3"}'; then
    echo "PASS: found netmon_bytes_sent_total for python3"
    RESULT=0
else
    echo "FAIL: no netmon_bytes_sent_total metric found for python3"
    echo "$METRICS"
    RESULT=1
fi

sudo kill "$AGENT_PID"
exit $RESULT
```

- [ ] **Step 3: Make it executable and run it (under WSL2, with root)**

```bash
chmod +x test/integration/run_integration_test.sh
./test/integration/run_integration_test.sh
```

Expected: `PASS: found netmon_bytes_sent_total for python3`

- [ ] **Step 4: Commit**

```bash
git add test/integration
git commit -m "test: add integration test generating known TCP traffic"
```

---

### Task 8: Deploy stack (Prometheus + Grafana) and README

**Files:**
- Create: `deploy/docker-compose.yml`
- Create: `deploy/prometheus/prometheus.yml`
- Create: `deploy/grafana/provisioning/datasources/prometheus.yml`
- Create: `deploy/grafana/provisioning/dashboards/dashboard.yml`
- Create: `deploy/grafana/dashboards/netmon.json`
- Create: `README.md`

**Interfaces:**
- Consumes: the agent's `/metrics` endpoint on `:9200` (Task 6), reached by
  Prometheus via `host.docker.internal:9200` from inside the compose network.

- [ ] **Step 1: Write the Prometheus scrape config**

```yaml
# deploy/prometheus/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "netmon"
    static_configs:
      - targets: ["host.docker.internal:9200"]
```

- [ ] **Step 2: Write the docker-compose file**

```yaml
# deploy/docker-compose.yml
services:
  prometheus:
    image: prom/prometheus:v2.54.1
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    ports:
      - "9090:9090"
    extra_hosts:
      - "host.docker.internal:host-gateway"

  grafana:
    image: grafana/grafana:11.2.0
    depends_on:
      - prometheus
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
      - ./grafana/dashboards:/etc/grafana/dashboards:ro
    ports:
      - "3000:3000"
```

- [ ] **Step 3: Write the Grafana provisioning files**

```yaml
# deploy/grafana/provisioning/datasources/prometheus.yml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
```

```yaml
# deploy/grafana/provisioning/dashboards/dashboard.yml
apiVersion: 1
providers:
  - name: netmon
    folder: netmon
    type: file
    options:
      path: /etc/grafana/dashboards
```

- [ ] **Step 4: Write the Grafana dashboard**

```json
{
  "title": "ebpf-netmon",
  "schemaVersion": 39,
  "panels": [
    {
      "title": "Bytes sent by process",
      "type": "timeseries",
      "gridPos": { "h": 8, "w": 12, "x": 0, "y": 0 },
      "targets": [
        { "expr": "rate(netmon_bytes_sent_total[1m])", "legendFormat": "{{process}}" }
      ]
    },
    {
      "title": "Bytes received by process",
      "type": "timeseries",
      "gridPos": { "h": 8, "w": 12, "x": 12, "y": 0 },
      "targets": [
        { "expr": "rate(netmon_bytes_received_total[1m])", "legendFormat": "{{process}}" }
      ]
    },
    {
      "title": "Retransmissions by process",
      "type": "timeseries",
      "gridPos": { "h": 8, "w": 12, "x": 0, "y": 8 },
      "targets": [
        { "expr": "increase(netmon_retransmits_total[1m])", "legendFormat": "{{process}}" }
      ]
    },
    {
      "title": "Max connect latency by process",
      "type": "timeseries",
      "gridPos": { "h": 8, "w": 12, "x": 12, "y": 8 },
      "targets": [
        { "expr": "netmon_connect_latency_seconds", "legendFormat": "{{process}}" }
      ]
    }
  ]
}
```

- [ ] **Step 5: Write the README**

```markdown
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

- Linux kernel ≥ 5.8 with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
- On Windows: WSL2. If `wsl --status` fails or `wsl.exe` errors with
  `REGDB_E_CLASSNOTREG`, WSL is not installed — run, as Administrator:
  ```
  wsl --install
  ```
  then reboot. If it still fails, enable manually via
  `Optional Features > Windows Subsystem for Linux` and
  `Virtual Machine Platform`, then reboot and retry `wsl --install`.
- Inside WSL2: `clang`, `llvm`, `libbpf-dev`, `linux-tools-generic`, Go 1.22+,
  Docker (or Docker Desktop with WSL2 integration enabled).

## Build & run

    make generate   # regenerate Go bindings from bpf/tcp_probes.c
    make build       # produces agent/bin/netmon
    sudo ./agent/bin/netmon   # root/CAP_BPF required to load eBPF programs

## Observability stack

    make up   # starts Prometheus (:9090) and Grafana (:3000, admin/admin)

The `netmon` dashboard is provisioned automatically in Grafana.

## Testing

    make test                              # unit tests (no kernel needed)
    ./test/integration/run_integration_test.sh   # integration test (needs root, Linux)

## Scope

TCP/IPv4 only, single host, no alerting — see
`docs/superpowers/specs/2026-09-22-ebpf-netmon-design.md` for the full design
and explicit non-goals.
```

- [ ] **Step 6: Commit**

```bash
git add deploy README.md
git commit -m "feat: add Prometheus/Grafana deploy stack and README"
```

---

## Definition of done

- [ ] `make test` passes (unit tests, no kernel required)
- [ ] `make generate && make build` succeeds under WSL2
- [ ] `./test/integration/run_integration_test.sh` passes under WSL2 with root
- [ ] `make up` brings up Grafana with the `netmon` dashboard showing live data
      after generating some traffic
