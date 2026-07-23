package analytics

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/mmt/mmt-studio-core/oam/pm"
)

var (
	datasetCSVPath = "nwdaf_feature_dataset.csv"
	datasetMu      sync.Mutex
)

// AppendFeatureVector appends one feature-vector row to a CSV dataset.
//
// The CSV file is created on first use, the header is written once, and
// subsequent calls append one row per collection cycle.
func AppendFeatureVector(features []float64) error {
	if len(features) != 5 {
		return fmt.Errorf("expected exactly 5 features, got %d", len(features))
	}
	datasetMu.Lock()
	defer datasetMu.Unlock()

	if err := ensureDatasetFile(); err != nil {
		return err
	}

	file, err := os.OpenFile(datasetCSVPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	if err := writer.Write(featuresToStrings(features)); err != nil {
		return err
	}
	writer.Flush()
	return writer.Error()
}

func ensureDatasetFile() error {
	info, err := os.Stat(datasetCSVPath)
	if err == nil {
		if info.Size() > 0 {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	if dir := filepath.Dir(datasetCSVPath); dir != "." && dir != string(os.PathSeparator) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	file, err := os.OpenFile(datasetCSVPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	header := []string{pm.AuthAtt, pm.AuthFail, pm.AuthFailMAC, pm.SMSessAtt, pm.SMSessFail}
	if err := writer.Write(header); err != nil {
		return err
	}
	writer.Flush()
	return writer.Error()
}

func featuresToStrings(features []float64) []string {
	values := make([]string, len(features))
	for i, value := range features {
		values[i] = fmt.Sprintf("%.15g", value)
	}
	return values
}
