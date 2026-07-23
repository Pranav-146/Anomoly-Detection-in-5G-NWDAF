package analytics

import (
	"fmt"

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
		return nil, nil
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
		features = append(features, toFloat(pmCounters[key]))
	}
	if len(features) != 5 {
		return nil, fmt.Errorf("expected exactly 5 features, got %d", len(features))
	}

	return features, nil
}
