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
		key     bpf.ConnKey
		val     bpf.ConnStats
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
	bpfKey := bpf.ConnKey{
		Pid: key.PID, Saddr: key.SAddr, Daddr: key.DAddr,
		Sport: key.SPort, Dport: key.DPort,
	}
	return r.m.Delete(&bpfKey)
}
