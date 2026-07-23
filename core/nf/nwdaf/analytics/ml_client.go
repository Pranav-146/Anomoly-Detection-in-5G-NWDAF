package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"time"
)

var (
	// DetectorMode selects which abnormal-behaviour detector is used. The
	// fixed threshold detector remains the default and is never replaced by ML.
	DetectorMode = envOrDefault("NWDAF_DETECTOR_MODE", "threshold")

	// MLServiceURL is the endpoint used by the optional ML detector.
	MLServiceURL = envOrDefault("NWDAF_ML_SERVICE_URL", "http://localhost:8000/predict")

	// MLHTTPClient is replaceable by tests; production uses the timeout below.
	MLHTTPClient HTTPDoer = &http.Client{Timeout: 3 * time.Second}
)

// HTTPDoer is the subset of http.Client used by the ML client.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type PredictionRequest struct {
	Features []float64 `json:"features"`
}

type PredictionResponse struct {
	Anomaly bool    `json:"anomaly"`
	Score   float64 `json:"score"`
}

// Predict sends features to the external ML inference service.
//
// The client is intentionally isolated from the rest of NWDAF and fails
// safely when the service is unavailable or returns malformed data.
func Predict(features []float64) (bool, float64, error) {
	if len(features) != 5 {
		return false, 0, fmt.Errorf("expected exactly 5 features, got %d", len(features))
	}
	for i, feature := range features {
		if math.IsNaN(feature) || math.IsInf(feature, 0) {
			return false, 0, fmt.Errorf("feature %d must be finite", i)
		}
	}

	payload := PredictionRequest{Features: features}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, 0, fmt.Errorf("marshal prediction request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, MLServiceURL, bytes.NewReader(body))
	if err != nil {
		return false, 0, fmt.Errorf("create prediction request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := MLHTTPClient.Do(req)
	if err != nil {
		return false, 0, fmt.Errorf("prediction request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return false, 0, fmt.Errorf("prediction request returned HTTP %d", resp.StatusCode)
	}

	var wire struct {
		Anomaly *bool    `json:"anomaly"`
		Score   *float64 `json:"score"`
	}
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return false, 0, fmt.Errorf("decode prediction response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return false, 0, fmt.Errorf("prediction response contains trailing JSON")
		}
		return false, 0, fmt.Errorf("read prediction response: %w", err)
	}
	if wire.Anomaly == nil || wire.Score == nil {
		return false, 0, fmt.Errorf("prediction response must contain anomaly and score")
	}

	if math.IsNaN(*wire.Score) || math.IsInf(*wire.Score, 0) {
		return false, 0, fmt.Errorf("prediction score must be finite")
	}

	return *wire.Anomaly, *wire.Score, nil
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
