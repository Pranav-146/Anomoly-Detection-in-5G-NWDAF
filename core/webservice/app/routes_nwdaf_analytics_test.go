// Copyright (c) 2026 MakeMyTechnology. All rights reserved.

package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mmt/mmt-studio-core/db/engine"
	"github.com/mmt/mmt-studio-core/nf/nwdaf"
	analytics "github.com/mmt/mmt-studio-core/nf/nwdaf/analytics"
)

func setupNWDAFTest(t *testing.T) *Server {
	engine.Close()
	engine.DBFilePath = filepath.Join(t.TempDir(), "sacore.db")
	if err := engine.EnsureSchema(); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	nwdaf.DefaultService = nwdaf.NewService(30)

	s := &Server{Router: chi.NewRouter(), routes: make(map[string]string)}
	s.registerNWDAFAnalyticsRoutes()
	return s
}

func parseJSONResponse(t *testing.T, res *httptest.ResponseRecorder) map[string]any {
	var payload map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if ok, _ := payload["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, got %#v", payload["ok"])
	}
	return payload
}

func parseErrorResponse(t *testing.T, res *httptest.ResponseRecorder) string {
	var payload map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	err, _ := payload["error"].(string)
	return err
}

func TestNWDAFAnalyticsMinConfidenceFiltersOutLowConfidenceResults(t *testing.T) {
	s := setupNWDAFTest(t)

	dp := analytics.DataPoint{
		SourceNF:    "AMF",
		AnalyticsID: analytics.AnalyticsAbnormalBehaviour,
		IMSI:        "imsi-001010126",
		DNN:         "internet",
		CollectedAt: float64(time.Now().Unix()),
		DataJSON:    `{"pm_counters":{"AUTH.Att":1,"AUTH.Fail":0,"AUTH.FailMAC":0,"SM.SessAtt":0,"SM.SessFail":0},"attribution":{},"attribution_rows":0}`,
	}
	if _, err := nwdaf.DefaultService.IngestDataPoint(dp); err != nil {
		t.Fatalf("failed to ingest data point: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/nwdaf/analytics/"+analytics.AnalyticsAbnormalBehaviour+"?min_confidence=0.99", nil)
	res := httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.Code)
	}

	payload := parseJSONResponse(t, res)
	if payload["result"] != nil {
		t.Fatalf("expected filtered result to be nil, got %#v", payload["result"])
	}
	if filtered, ok := payload["filtered_out"].(bool); !ok || !filtered {
		t.Fatalf("expected filtered_out=true, got %#v", payload["filtered_out"])
	}
}

func TestNWDAFAnalyticsRoutesRejectUnknownAnalyticsID(t *testing.T) {
	s := setupNWDAFTest(t)

	req := httptest.NewRequest(http.MethodGet, "/api/nwdaf/analytics/UNKNOWN_ID", nil)
	res := httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for unknown analytics_id, got %d", res.Code)
	}
	if err := parseErrorResponse(t, res); err == "" {
		t.Fatal("expected non-empty error message for unknown analytics_id")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/nwdaf/export?analytics_id=UNKNOWN_ID", nil)
	res = httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for export unknown analytics_id, got %d", res.Code)
	}
	if err := parseErrorResponse(t, res); err == "" {
		t.Fatal("expected non-empty error message for export unknown analytics_id")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/nwdaf/recent?analytics_id=UNKNOWN_ID", nil)
	res = httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for recent unknown analytics_id, got %d", res.Code)
	}
	if err := parseErrorResponse(t, res); err == "" {
		t.Fatal("expected non-empty error message for recent unknown analytics_id")
	}
}

func TestNWDAFAnalyticsRouteIncludesAbnormalBehaviourAttribution(t *testing.T) {
	s := setupNWDAFTest(t)

	dp := analytics.DataPoint{
		SourceNF:    "AMF",
		AnalyticsID: analytics.AnalyticsAbnormalBehaviour,
		IMSI:        "imsi-001010123",
		DNN:         "internet",
		CollectedAt: float64(time.Now().Unix()),
		DataJSON:    `{"pm_counters":{"AUTH.Att":10,"AUTH.Fail":5,"AUTH.FailMAC":0,"SM.SessAtt":0,"SM.SessFail":0},"attribution":{"imsi-001010123":{"supi":"imsi-001010123","origin":"gNB-1","cell_id":"cell-42","attempt_count":1,"failure_count":1,"distinct_origins":1}},"attribution_rows":1}`,
	}
	if _, err := nwdaf.DefaultService.IngestDataPoint(dp); err != nil {
		t.Fatalf("failed to ingest data point: %v", err)
	}

	direct := nwdaf.DefaultService.GetAnalytics(analytics.AnalyticsAbnormalBehaviour, "", "", 300)
	if direct.Result["attribution"] == nil {
		t.Fatalf("direct GetAnalytics expected attribution, got %#v", direct.Result)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/nwdaf/analytics/"+analytics.AnalyticsAbnormalBehaviour, nil)
	res := httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", res.Code)
	}

	payload := parseJSONResponse(t, res)
	envelope, ok := payload["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected envelope result object, got %#v", payload["result"])
	}

	body, ok := envelope["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected analytics result body object, got %#v", envelope["result"])
	}

	attribution, ok := body["attribution"].(map[string]any)
	if !ok || len(attribution) == 0 {
		t.Fatalf("expected attribution object in analytics result, got %#v", body["attribution"])
	}

	if rows, ok := body["attribution_rows"].(float64); !ok || rows != 1 {
		t.Fatalf("expected attribution_rows=1, got %#v", body["attribution_rows"])
	}
}

func TestNWDAFAnalyticsRoutesSupportExportRecentStatusAndSubscriptions(t *testing.T) {
	s := setupNWDAFTest(t)

	dp := analytics.DataPoint{
		SourceNF:    "AMF",
		AnalyticsID: analytics.AnalyticsAbnormalBehaviour,
		IMSI:        "imsi-001010124",
		DNN:         "internet",
		CollectedAt: float64(time.Now().Unix()),
		DataJSON:    `{"pm_counters":{"AUTH.Att":10,"AUTH.Fail":1,"AUTH.FailMAC":0,"SM.SessAtt":1,"SM.SessFail":0},"attribution":{"imsi-001010124":{"supi":"imsi-001010124","origin":"gNB-2","cell_id":"cell-100","attempt_count":1,"failure_count":0,"distinct_origins":1}},"attribution_rows":1}`,
	}
	if _, err := nwdaf.DefaultService.IngestDataPoint(dp); err != nil {
		t.Fatalf("failed to ingest data point: %v", err)
	}

	// Analytics aggregator route
	req := httptest.NewRequest(http.MethodGet, "/api/nwdaf/analytics?window_sec=300", nil)
	res := httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200 for aggregator, got %d", res.Code)
	}
	payload := parseJSONResponse(t, res)
	analyticsMap, ok := payload["analytics"].(map[string]any)
	if !ok {
		t.Fatalf("expected analytics object, got %#v", payload["analytics"])
	}
	if _, ok := analyticsMap[analytics.AnalyticsAbnormalBehaviour]; !ok {
		t.Fatalf("expected analytics map to include %s", analytics.AnalyticsAbnormalBehaviour)
	}

	// Persisted export route
	postBody := []byte(`{"source_nf":"AMF","analytics_id":"ABNORMAL_BEHAVIOUR","imsi":"imsi-001010124","dnn":"internet","data_json":"{\"pm_counters\":{\"AUTH.Att\":10,\"AUTH.Fail\":1,\"AUTH.FailMAC\":0,\"SM.SessAtt\":1,\"SM.SessFail\":0},\"attribution\":{\"imsi-001010124\":{\"supi\":\"imsi-001010124\",\"origin\":\"gNB-2\",\"cell_id\":\"cell-100\",\"attempt_count\":1,\"failure_count\":0,\"distinct_origins\":1}},\"attribution_rows\":1}","collected_at":` + strconv.FormatFloat(float64(time.Now().Unix()), 'f', 0, 64) + `}`)
	req = httptest.NewRequest(http.MethodPost, "/api/nwdaf/data", bytes.NewReader(postBody))
	req.Header.Set("Content-Type", "application/json")
	res = httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200 for data ingestion, got %d", res.Code)
	}
	payload = parseJSONResponse(t, res)
	if _, ok := payload["id"].(float64); !ok {
		t.Fatalf("expected data ingestion to return numeric id, got %#v", payload["id"])
	}

	req = httptest.NewRequest(http.MethodGet, "/api/nwdaf/export?analytics_id=ABNORMAL_BEHAVIOUR&limit=10", nil)
	res = httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200 for export, got %d", res.Code)
	}
	payload = parseJSONResponse(t, res)
	records, ok := payload["rows"].([]any)
	if !ok || len(records) == 0 {
		t.Fatalf("expected export rows, got %#v", payload["rows"])
	}

	req = httptest.NewRequest(http.MethodGet, "/api/nwdaf/recent?analytics_id=ABNORMAL_BEHAVIOUR&limit=5", nil)
	res = httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200 for recent, got %d", res.Code)
	}
	payload = parseJSONResponse(t, res)
	recent, ok := payload["recent"].([]any)
	if !ok || len(recent) == 0 {
		t.Fatalf("expected recent analytics rows, got %#v", payload["recent"])
	}

	req = httptest.NewRequest(http.MethodGet, "/api/nwdaf/status", nil)
	res = httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200 for status, got %d", res.Code)
	}
	payload = parseJSONResponse(t, res)
	ingest, ok := payload["ingest"].(map[string]any)
	if !ok {
		t.Fatalf("expected ingest map in status, got %#v", payload["ingest"])
	}
	if total, ok := ingest["total"].(float64); !ok || total < 1 {
		t.Fatalf("expected ingest.total >= 1, got %#v", ingest["total"])
	}
}

func TestNWDAFSubscriptionLifecycle(t *testing.T) {
	s := setupNWDAFTest(t)

	payloadBody := map[string]any{
		"consumer_nf":  "TEST_CONSUMER",
		"analytics_id": analytics.AnalyticsAbnormalBehaviour,
		"target_imsi":  "imsi-001010125",
		"target_dnn":   "internet",
		"callback_url": "http://example.com/callback",
		"interval_sec": 30,
	}
	body, _ := json.Marshal(payloadBody)

	req := httptest.NewRequest(http.MethodPost, "/api/nwdaf/subscriptions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200 for subscription create, got %d", res.Code)
	}
	payload := parseJSONResponse(t, res)
	subID, ok := payload["sub_id"].(string)
	if !ok || subID == "" {
		t.Fatalf("expected subscription id, got %#v", payload["sub_id"])
	}

	req = httptest.NewRequest(http.MethodGet, "/api/nwdaf/subscriptions", nil)
	res = httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200 for subscriptions list, got %d", res.Code)
	}
	payload = parseJSONResponse(t, res)
	subscriptions, ok := payload["subscriptions"].([]any)
	if !ok || len(subscriptions) != 1 {
		t.Fatalf("expected one active subscription, got %#v", payload["subscriptions"])
	}

	req = httptest.NewRequest(http.MethodGet, "/api/nwdaf/subscriptions/"+subID, nil)
	res = httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200 for subscription get, got %d", res.Code)
	}
	payload = parseJSONResponse(t, res)
	subscription, ok := payload["subscription"].(map[string]any)
	if !ok || subscription["sub_id"] != subID {
		t.Fatalf("expected subscription object with id %s, got %#v", subID, payload["subscription"])
	}

	patchBody := map[string]any{"interval_sec": 120, "status": "suspended"}
	patchJSON, _ := json.Marshal(patchBody)
	req = httptest.NewRequest(http.MethodPatch, "/api/nwdaf/subscriptions/"+subID, bytes.NewReader(patchJSON))
	req.Header.Set("Content-Type", "application/json")
	res = httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200 for subscription patch, got %d", res.Code)
	}
	payload = parseJSONResponse(t, res)
	updated, ok := payload["subscription"].(map[string]any)
	if !ok || updated["status"] != "suspended" {
		t.Fatalf("expected suspended status after patch, got %#v", payload["subscription"])
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/nwdaf/subscriptions/"+subID, nil)
	res = httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected status 200 for subscription delete, got %d", res.Code)
	}
	payload = parseJSONResponse(t, res)
	if payload["sub_id"] != subID {
		t.Fatalf("expected delete response with sub_id %s, got %#v", subID, payload["sub_id"])
	}

	req = httptest.NewRequest(http.MethodGet, "/api/nwdaf/subscriptions", nil)
	res = httptest.NewRecorder()
	s.Router.ServeHTTP(res, req)
	payload = parseJSONResponse(t, res)
	subscriptions, ok = payload["subscriptions"].([]any)
	if !ok || len(subscriptions) != 0 {
		t.Fatalf("expected zero active subscriptions after delete, got %#v", payload["subscriptions"])
	}
}
