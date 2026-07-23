package analytics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var (
	// DetectorMode selects which abnormal-behaviour detector is used.
	DetectorMode = "threshold"

	// MLServiceURL is the endpoint used by the ML detector.
	MLServiceURL = "http://localhost:8000/predict"
)

type PredictionRequest struct {
	Features []float64 `json:"features"`
}

type PredictionResponse struct {
	Prediction bool    `json:"prediction"`
	Confidence float64 `json:"confidence"`
}

// Predict sends features to the external ML inference service.
//
// The client is intentionally isolated from the rest of NWDAF and fails
// safely when the service is unavailable or returns malformed data.
func Predict(features []float64) (bool, float64, error) {
	payload := PredictionRequest{Features: features}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, 0, fmt.Errorf("marshal prediction request: %w", err)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodPost, MLServiceURL, bytes.NewReader(body))
	if err != nil {
		return false, 0, fmt.Errorf("create prediction request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, 0, fmt.Errorf("prediction request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return false, 0, fmt.Errorf("prediction request returned HTTP %d", resp.StatusCode)
	}

	var predictionResp PredictionResponse
	if err := json.NewDecoder(resp.Body).Decode(&predictionResp); err != nil {
		return false, 0, fmt.Errorf("decode prediction response: %w", err)
	}

	if predictionResp.Confidence < 0 || predictionResp.Confidence > 1 {
		return false, 0, fmt.Errorf("prediction confidence out of range: %.3f", predictionResp.Confidence)
	}

	return predictionResp.Prediction, predictionResp.Confidence, nil
}
