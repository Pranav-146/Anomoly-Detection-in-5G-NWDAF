package amf

import (
	"fmt"
	"sync"
)

// AttributionRecord stores lightweight origin attribution evidence for a SUPI.
type AttributionRecord struct {
	SUPI            string
	Origin          string
	CellID          string
	LastSeenAt      int64
	AttemptCount    int64
	FailureCount    int64
	DistinctOrigins int64
}

var (
	attributionMu    sync.RWMutex
	attributionStore = map[string]*AttributionRecord{}
)

// RecordAuthFailure stores a failure event for the given subscriber and origin.
func RecordAuthFailure(supi, origin, cellID string) {
	attributionMu.Lock()
	defer attributionMu.Unlock()

	record, ok := attributionStore[supi]
	if !ok {
		record = &AttributionRecord{SUPI: supi}
		attributionStore[supi] = record
	}

	record.AttemptCount++
	record.FailureCount++
	record.Origin = origin
	record.CellID = cellID
	record.LastSeenAt = 0
	record.DistinctOrigins++
}

// GetAttributionRecord returns the current attribution record for a SUPI.
func GetAttributionRecord(supi string) *AttributionRecord {
	attributionMu.RLock()
	defer attributionMu.RUnlock()
	return attributionStore[supi]
}

// SnapshotAttribution returns a copy of the current store for inspection.
func SnapshotAttribution() map[string]*AttributionRecord {
	attributionMu.RLock()
	defer attributionMu.RUnlock()
	out := make(map[string]*AttributionRecord, len(attributionStore))
	for k, v := range attributionStore {
		copyRecord := *v
		out[k] = &copyRecord
	}
	return out
}

// ClearAttribution clears the in-memory attribution store.
func ClearAttribution() {
	attributionMu.Lock()
	defer attributionMu.Unlock()
	attributionStore = map[string]*AttributionRecord{}
}

// String returns a human-readable representation of the record.
func (r *AttributionRecord) String() string {
	if r == nil {
		return "<nil>"
	}
	return fmt.Sprintf("SUPI=%s origin=%s cell=%s failures=%d attempts=%d", r.SUPI, r.Origin, r.CellID, r.FailureCount, r.AttemptCount)
}
