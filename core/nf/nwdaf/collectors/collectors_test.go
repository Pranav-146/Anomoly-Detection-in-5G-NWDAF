package collectors

import (
	"encoding/json"
	"testing"

	"github.com/mmt/mmt-studio-core/nf/attribution"
	"github.com/mmt/mmt-studio-core/nf/nwdaf/analytics"
)

func TestCollectAMFDataIncludesAttributionSnapshot(t *testing.T) {
	attribution.Clear()
	attribution.RecordAuthFailure("imsi-001010123", "gNB-1", "cell-42")

	points := CollectAMFData()
	var found bool
	for _, dp := range points {
		if dp.AnalyticsID != analytics.AnalyticsAbnormalBehaviour {
			continue
		}
		found = true
		var payload map[string]any
		if err := json.Unmarshal([]byte(dp.DataJSON), &payload); err != nil {
			t.Fatalf("unmarshal abnormal behaviour payload: %v", err)
		}

		att, ok := payload["attribution"].(map[string]any)
		if !ok {
			t.Fatalf("expected attribution object in payload, got %#v", payload["attribution"])
		}
		if len(att) != 1 {
			t.Fatalf("expected 1 attribution record, got %d", len(att))
		}
		if payload["attribution_rows"].(float64) != 1 {
			t.Fatalf("expected attribution_rows=1, got %#v", payload["attribution_rows"])
		}
		break
	}

	if !found {
		t.Fatal("expected abnormal behaviour data point")
	}
}
