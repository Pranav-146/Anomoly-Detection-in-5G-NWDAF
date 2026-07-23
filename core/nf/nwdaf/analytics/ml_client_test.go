package analytics

import (
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func withMLClientTestServer(t *testing.T, response string, status int) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/predict" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
		}
		if !strings.Contains(string(body), `"features":[1,2,3,4,5]`) {
			t.Errorf("unexpected request body: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, response)
	}))
	t.Cleanup(server.Close)
	MLServiceURL = server.URL + "/predict"
}

func TestPredictAcceptsMLServiceContract(t *testing.T) {
	oldURL, oldClient := MLServiceURL, MLHTTPClient
	t.Cleanup(func() { MLServiceURL, MLHTTPClient = oldURL, oldClient })
	withMLClientTestServer(t, `{"anomaly":true,"score":0.75}`, http.StatusOK)

	anomaly, score, err := Predict([]float64{1, 2, 3, 4, 5})
	if err != nil {
		t.Fatalf("Predict returned error: %v", err)
	}
	if !anomaly || score != 0.75 {
		t.Fatalf("unexpected result: anomaly=%v score=%v", anomaly, score)
	}
}

func TestPredictRejectsInvalidResponsesAndInputs(t *testing.T) {
	oldURL, oldClient := MLServiceURL, MLHTTPClient
	t.Cleanup(func() { MLServiceURL, MLHTTPClient = oldURL, oldClient })

	if _, _, err := Predict([]float64{1, 2}); err == nil {
		t.Fatal("expected wrong feature count error")
	}
	if _, _, err := Predict([]float64{1, 2, 3, 4, math.NaN()}); err == nil {
		t.Fatal("expected non-finite feature error")
	}

	withMLClientTestServer(t, `{"prediction":true,"confidence":0.9}`, http.StatusOK)
	if _, _, err := Predict([]float64{1, 2, 3, 4, 5}); err == nil {
		t.Fatal("expected stale response contract error")
	}

	withMLClientTestServer(t, `service unavailable`, http.StatusServiceUnavailable)
	if _, _, err := Predict([]float64{1, 2, 3, 4, 5}); err == nil {
		t.Fatal("expected HTTP error")
	}
}
