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
