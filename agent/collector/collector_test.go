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
