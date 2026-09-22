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

// attachProbes attaches every kprobe and returns the links that succeeded.
// A probe that fails to attach (old kernel, missing symbol) is logged and
// skipped — the agent keeps running with whichever probes succeeded.
func attachProbes(objs *bpf.TcpprobesObjects) []link.Link {
	var links []link.Link
	type attempt struct {
		name   string
		attach func() (link.Link, error)
	}
	attempts := []attempt{
		{"tcp_connect", func() (link.Link, error) {
			return link.Kprobe("tcp_connect", objs.TraceTcpConnect, nil)
		}},
		{"tcp_close", func() (link.Link, error) {
			return link.Kprobe("tcp_close", objs.TraceTcpClose, nil)
		}},
		{"tcp_retransmit_skb", func() (link.Link, error) {
			return link.Kprobe("tcp_retransmit_skb", objs.TraceTcpRetransmitSkb, nil)
		}},
		{"tcp_sendmsg", func() (link.Link, error) {
			return link.Kprobe("tcp_sendmsg", objs.TraceTcpSendmsg, nil)
		}},
		{"tcp_cleanup_rbuf", func() (link.Link, error) {
			return link.Kprobe("tcp_cleanup_rbuf", objs.TraceTcpRecvmsg, nil)
		}},
	}

	for _, a := range attempts {
		l, err := a.attach()
		if err != nil {
			log.Printf("main: failed to attach probe %s: %v — continuing without it", a.name, err)
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

	reader := bpfreader.NewBPFMapReader(objs.ConnStatsMap)
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
