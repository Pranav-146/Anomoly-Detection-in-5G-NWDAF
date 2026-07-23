package analytics

// ExtractFeatures converts existing PM counters into a simple, ordered
// feature vector for future ML integration.
//
// Feature order is intentionally fixed and must remain stable for future
// inference:
//   0 -> AUTH.Att
//   1 -> AUTH.Fail
//   2 -> AUTH.FailMAC
//   3 -> SM.SessAtt
//   4 -> SM.SessFail
//
// The current implementation exposes the already-available counters directly
// without introducing new preprocessing or rolling-window logic.
func ExtractFeatures(pmCounters map[string]any) ([]float64, error) {
	if pmCounters == nil {
		return []float64{}, nil
	}

	featureKeys := []string{
		"AUTH.Att",
		"AUTH.Fail",
		"AUTH.FailMAC",
		"SM.SessAtt",
		"SM.SessFail",
	}

	features := make([]float64, 0, len(featureKeys))
	for _, key := range featureKeys {
		features = append(features, toFloat(pmCounters[key]))
	}

	return features, nil
}
