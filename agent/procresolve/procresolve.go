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
