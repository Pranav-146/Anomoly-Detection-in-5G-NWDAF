package attribution
package attribution

import (
	"fmt"
	"sync"
)

// Record stores lightweight origin attribution evidence for a SUPI.
type Record struct {
	SUPI            string
	Origin          string
	CellID          string
	LastSeenAt      int64
	AttemptCount    int64
	FailureCount    int64
	DistinctOrigins int64
}

var (
	mu    sync.RWMutex
	store = map[string]*Record{}
)

// RecordAuthFailure stores a failure event for the given subscriber and origin.
func RecordAuthFailure(supi, origin, cellID string) {
	mu.Lock()
	defer mu.Unlock()

	record, ok := store[supi]
	if !ok {
		record = &Record{SUPI: supi}
		store[supi] = record
	}

	record.AttemptCount++
	record.FailureCount++
	record.Origin = origin
	record.CellID = cellID
	record.LastSeenAt = 0
	record.DistinctOrigins++
}

// GetRecord returns the current attribution record for a SUPI.
func GetRecord(supi string) *Record {
	mu.RLock()
	defer mu.RUnlock()
	return store[supi]
}

// Snapshot returns a copy of the current store for inspection.
func Snapshot() map[string]*Record {
	mu.RLock()
	defer mu.RUnlock()
	out := make(map[string]*Record, len(store))
	for k, v := range store {
		copyRecord := *v
		out[k] = &copyRecord
	}
	return out
}

// Clear clears the in-memory attribution store.
func Clear() {
	mu.Lock()
	defer mu.Unlock()
	store = map[string]*Record{}
}

// String returns a human-readable representation of the record.
func (r *Record) String() string {
	if r == nil {
		return "<nil>"
	}
	return fmt.Sprintf("SUPI=%s origin=%s cell=%s failures=%d attempts=%d", r.SUPI, r.Origin, r.CellID, r.FailureCount, r.AttemptCount)
}
