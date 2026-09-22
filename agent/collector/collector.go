package collector

import (
	"log"

	"github.com/yarra/ebpf-netmon/agent/procresolve"
)

type ConnKey struct {
	PID          uint32
	SAddr, DAddr uint32
	SPort, DPort uint16
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
