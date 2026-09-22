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
