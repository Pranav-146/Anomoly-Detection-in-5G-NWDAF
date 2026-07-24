// Copyright (c) 2026 MakeMyTechnology. All rights reserved.

package nwdaf

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mmt/mmt-studio-core/db/engine"
	analytics "github.com/mmt/mmt-studio-core/nf/nwdaf/analytics"
)

func setupServiceTest(t *testing.T) *Service {
	engine.Close()
	engine.DBFilePath = filepath.Join(t.TempDir(), "sacore.db")
	if err := engine.EnsureSchema(); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}
	svc := NewService(30)
	return svc
}

func TestIngestDataPointExportRecentAndAnalyticsPersistence(t *testing.T) {
	svc := setupServiceTest(t)
	dp := analytics.DataPoint{
		SourceNF:    "AMF",
		AnalyticsID: analytics.AnalyticsAbnormalBehaviour,
		IMSI:        "imsi-001010126",
		DNN:         "internet",
		CollectedAt: float64(time.Now().Unix()),
		DataJSON:    `{"pm_counters":{"AUTH.Att":10,"AUTH.Fail":2,"AUTH.FailMAC":1,"SM.SessAtt":1,"SM.SessFail":0},"attribution":{"imsi-001010126":{"supi":"imsi-001010126","origin":"gNB-3","cell_id":"cell-200","attempt_count":1,"failure_count":0,"distinct_origins":1}},"attribution_rows":1}`,
	}
	if _, err := svc.IngestDataPoint(dp); err != nil {
		t.Fatalf("failed to ingest data point: %v", err)
	}

	stats := svc.IngestStats()
	total, ok := stats["total"].(int64)
	if !ok || total < 1 {
		t.Fatalf("expected ingest total >= 1, got %#v", stats["total"])
	}

	exported := svc.ExportDataPoints(analytics.AnalyticsAbnormalBehaviour, "imsi-001010126", 0, 10)
	if len(exported) != 1 {
		t.Fatalf("expected one exported data point, got %d", len(exported))
	}
	if exported[0]["analytics_id"] != analytics.AnalyticsAbnormalBehaviour {
		t.Fatalf("expected exported analytics_id %s, got %#v", analytics.AnalyticsAbnormalBehaviour, exported[0]["analytics_id"])
	}

	res := svc.GetAnalytics(analytics.AnalyticsAbnormalBehaviour, "", "", 300)
	if res.AnalyticsID != analytics.AnalyticsAbnormalBehaviour {
		t.Fatalf("expected analytics id %s, got %s", analytics.AnalyticsAbnormalBehaviour, res.AnalyticsID)
	}
	if res.Result["attribution"] == nil {
		t.Fatalf("expected attribution in analytics result, got %#v", res.Result)
	}

	recent := svc.GetRecentAnalytics(analytics.AnalyticsAbnormalBehaviour, 5)
	if len(recent) == 0 {
		t.Fatalf("expected recent analytics rows, got %#v", recent)
	}
	if _, ok := recent[0]["result_json"].(map[string]any); !ok {
		t.Fatalf("expected recent result_json map, got %#v", recent[0]["result_json"])
	}
}

func TestSubscriptionCRUDAndList(t *testing.T) {
	svc := setupServiceTest(t)

	subID := svc.Subscribe("TEST_NF", analytics.AnalyticsAbnormalBehaviour, "imsi-001010127", "internet", "", "http://example.com/callback", 60)
	if subID == "" {
		t.Fatal("expected non-empty subscription id")
	}

	row, err := svc.GetSubscription(subID)
	if err != nil {
		t.Fatalf("GetSubscription failed: %v", err)
	}
	if row == nil || row["sub_id"] != subID {
		t.Fatalf("expected subscription row with sub_id %s, got %#v", subID, row)
	}

	list := svc.ListSubscriptions()
	if len(list) != 1 {
		t.Fatalf("expected active subscription list length 1, got %d", len(list))
	}

	ok, err := svc.UpdateSubscription(subID, map[string]any{"target_dnn": "vpn", "status": "suspended"})
	if err != nil {
		t.Fatalf("UpdateSubscription failed: %v", err)
	}
	if !ok {
		t.Fatal("expected UpdateSubscription to report updated")
	}

	updated, err := svc.GetSubscription(subID)
	if err != nil {
		t.Fatalf("GetSubscription failed: %v", err)
	}
	if updated["status"] != "suspended" {
		t.Fatalf("expected updated status suspended, got %#v", updated["status"])
	}

	if !svc.Unsubscribe(subID) {
		t.Fatal("expected Unsubscribe to succeed")
	}

	list = svc.ListSubscriptions()
	if len(list) != 0 {
		t.Fatalf("expected zero active subscriptions after unsubscribe, got %d", len(list))
	}
}

func TestAnalyticsTargetFilteringAndCacheStatus(t *testing.T) {
	svc := setupServiceTest(t)
	now := float64(time.Now().Unix())

	points := []analytics.DataPoint{
		{SourceNF: "AMF", AnalyticsID: analytics.AnalyticsAbnormalBehaviour, IMSI: "imsi-001010128", DNN: "internet", DataJSON: `{"pm_counters":{"AUTH.Att":5,"AUTH.Fail":1}}`, CollectedAt: now},
		{SourceNF: "AMF", AnalyticsID: analytics.AnalyticsAbnormalBehaviour, IMSI: "imsi-001010129", DNN: "internet", DataJSON: `{"pm_counters":{"AUTH.Att":5,"AUTH.Fail":3}}`, CollectedAt: now},
	}
	for _, dp := range points {
		if _, err := svc.IngestDataPoint(dp); err != nil {
			t.Fatalf("failed to ingest data point: %v", err)
		}
	}

	svcStatus := svc.Status()
	if cached, ok := svcStatus["cached_data_points"].(int); !ok || cached < 2 {
		t.Fatalf("expected cached_data_points >= 2, got %#v", svcStatus["cached_data_points"])
	}

	res := svc.GetAnalytics(analytics.AnalyticsAbnormalBehaviour, "imsi-001010129", "internet", 300)
	if res.Result == nil {
		t.Fatal("expected analytics result map, got nil")
	}
}
