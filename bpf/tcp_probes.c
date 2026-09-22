//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

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
} conn_stats_map SEC(".maps");

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

    struct conn_stats *stats = bpf_map_lookup_elem(&conn_stats_map, &key);
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
    struct conn_stats *stats = bpf_map_lookup_elem(&conn_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&conn_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&conn_stats_map, &key);
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
    struct conn_stats *stats = bpf_map_lookup_elem(&conn_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&conn_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&conn_stats_map, &key);
        if (!stats)
            return 0;
    }
    __sync_fetch_and_add(&stats->bytes_sent, size);
    return 0;
}

// tcp_recvmsg doesn't carry a reliable "bytes copied" value on entry across
// kernel versions, so throughput-in is measured via tcp_cleanup_rbuf(sk,
// copied), which reports bytes actually copied to userspace. This is the
// same approach used by BCC's tcplife/tcptop tools, for the same reason.
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
    struct conn_stats *stats = bpf_map_lookup_elem(&conn_stats_map, &key);
    if (!stats) {
        bpf_map_update_elem(&conn_stats_map, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&conn_stats_map, &key);
        if (!stats)
            return 0;
    }
    __sync_fetch_and_add(&stats->bytes_recv, copied);
    return 0;
}
