package analytics

import (
	"fmt"
	"math"

	"github.com/mmt/mmt-studio-core/oam/pm"
)

// ExtractFeatures converts existing PM counters into a simple, ordered
// feature vector for future ML integration.
//
// Feature order is intentionally fixed and must remain stable for future
// inference:
//
//	0 -> AUTH.Att
//	1 -> AUTH.Fail
//	2 -> AUTH.FailMAC
//	3 -> SM.SessAtt
//	4 -> SM.SessFail
//
// The current implementation exposes the already-available counters directly
// without introducing new preprocessing or rolling-window logic.
func ExtractFeatures(pmCounters map[string]any) ([]float64, error) {
	if pmCounters == nil {
		return nil, fmt.Errorf("PM counters are required")
	}

	featureKeys := []string{
		pm.AuthAtt,
		pm.AuthFail,
		pm.AuthFailMAC,
		pm.SMSessAtt,
		pm.SMSessFail,
	}

	features := make([]float64, 0, len(featureKeys))
	for _, key := range featureKeys {
		value, ok := pmCounters[key]
		if !ok {
			features = append(features, 0)
			continue
		}
		converted, err := featureValue(value)
		if err != nil {
			return nil, fmt.Errorf("invalid PM counter %q: %w", key, err)
		}
		features = append(features, converted)
	}
	if len(features) != 5 {
		return nil, fmt.Errorf("expected exactly 5 features, got %d", len(features))
	}

	return features, nil
}

func featureValue(value any) (float64, error) {
	var converted float64
	switch number := value.(type) {
	case int:
		converted = float64(number)
	case int32:
		converted = float64(number)
	case int64:
		converted = float64(number)
	case uint:
		converted = float64(number)
	case uint32:
		converted = float64(number)
	case uint64:
		converted = float64(number)
	case float32:
		converted = float64(number)
	case float64:
		converted = number
	default:
		return 0, fmt.Errorf("expected numeric value, got %T", value)
	}
	if math.IsNaN(converted) || math.IsInf(converted, 0) {
		return 0, fmt.Errorf("value must be finite")
	}
	return converted, nil
}
