package analytics

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func abnormalTestPoint(data string) DataPoint {
	return DataPoint{
		AnalyticsID: AnalyticsAbnormalBehaviour,
		DataJSON:    data,
		CollectedAt: float64(time.Now().Unix()),
	}
}

func TestComputeMLAddsAnomalyWithoutRemovingThresholdAlerts(t *testing.T) {
	oldURL, oldClient, oldMode := MLServiceURL, MLHTTPClient, DetectorMode
	t.Cleanup(func() { MLServiceURL, MLHTTPClient, DetectorMode = oldURL, oldClient, oldMode })
	DetectorMode = "ml"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"anomaly":true,"score":0.8}`))
	}))
	t.Cleanup(server.Close)
	MLServiceURL = server.URL

	result := ComputeAnalytics(AnalyticsAbnormalBehaviour, []DataPoint{
		abnormalTestPoint(`{"pm_counters":{"AUTH.Att":10,"AUTH.Fail":5,"AUTH.FailMAC":0,"SM.SessAtt":0,"SM.SessFail":0}}`),
	}, 60)

	if !result.Result["anomaly_detected"].(bool) {
		t.Fatal("expected anomaly_detected")
	}
	alerts := result.Result["alerts"].([]map[string]any)
	if len(alerts) != 2 {
		t.Fatalf("expected threshold and ML alerts, got %#v", alerts)
	}
	if alerts[0]["type"] != "AUTH_FAILURE_SPIKE" || alerts[1]["type"] != "ML_ANOMALY" {
		t.Fatalf("unexpected alerts: %#v", alerts)
	}
}

func TestComputeMLFallsBackToThresholdOnServiceFailure(t *testing.T) {
	oldURL, oldClient, oldMode := MLServiceURL, MLHTTPClient, DetectorMode
	t.Cleanup(func() { MLServiceURL, MLHTTPClient, DetectorMode = oldURL, oldClient, oldMode })
	DetectorMode = "ml"
	MLServiceURL = "http://127.0.0.1:1/predict"

	result := ComputeAnalytics(AnalyticsAbnormalBehaviour, []DataPoint{
		abnormalTestPoint(`{"pm_counters":{"AUTH.Att":10,"AUTH.Fail":5,"AUTH.FailMAC":0,"SM.SessAtt":0,"SM.SessFail":0}}`),
	}, 60)

	alerts := result.Result["alerts"].([]map[string]any)
	if len(alerts) != 1 || alerts[0]["type"] != "AUTH_FAILURE_SPIKE" {
		t.Fatalf("expected unchanged threshold result, got %#v", alerts)
	}
	if result.Confidence != 0.7 {
		t.Fatalf("expected threshold confidence 0.7, got %v", result.Confidence)
	}
}
func TestComputeThresholdIncludesAttribution(t *testing.T) {
    points := []DataPoint{
        abnormalTestPoint(`{"pm_counters":{"AUTH.Att":10,"AUTH.Fail":5,"AUTH.FailMAC":0,"SM.SessAtt":0,"SM.SessFail":0},"attribution":{"imsi-001010123":{"supi":"imsi-001010123","origin":"gNB-1","cell_id":"cell-42","attempt_count":1,"failure_count":1,"distinct_origins":1}},"attribution_rows":1}`),
    }

    result := ComputeAnalytics(AnalyticsAbnormalBehaviour, points, 60)
    if result.Result["attribution"] == nil {
        t.Fatal("expected attribution in result")
    }
    if result.Result["attribution_rows"] != 1 {
        t.Fatalf("expected attribution_rows=1, got %#v", result.Result["attribution_rows"])
    }
}

func TestComputeMLIncludesAttribution(t *testing.T) {
    oldURL, oldClient, oldMode := MLServiceURL, MLHTTPClient, DetectorMode
    t.Cleanup(func() { MLServiceURL, MLHTTPClient, DetectorMode = oldURL, oldClient, oldMode })
    DetectorMode = "ml"
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        _, _ = w.Write([]byte(`{"anomaly":false,"score":0.2}`))
    }))
    t.Cleanup(server.Close)
    MLServiceURL = server.URL

    result := ComputeAnalytics(AnalyticsAbnormalBehaviour, []DataPoint{
        abnormalTestPoint(`{"pm_counters":{"AUTH.Att":10,"AUTH.Fail":5,"AUTH.FailMAC":0,"SM.SessAtt":0,"SM.SessFail":0},"attribution":{"imsi-001010123":{"supi":"imsi-001010123","origin":"gNB-1","cell_id":"cell-42","attempt_count":1,"failure_count":1,"distinct_origins":1}},"attribution_rows":1}`),
    }, 60)

    if result.Result["attribution"] == nil {
        t.Fatal("expected attribution in ML result")
    }
    if result.Result["attribution_rows"] != 1 {
        t.Fatalf("expected attribution_rows=1, got %#v", result.Result["attribution_rows"])
    }
}