package dataset

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const datasetFilename = "nwdaf_feature_dataset.csv"

var mu sync.Mutex

// AppendFeatureVector appends one feature-vector row to the NWDAF CSV dataset.
func AppendFeatureVector(features []float64) error {
	if len(features) != 5 {
		return fmt.Errorf("expected exactly 5 features, got %d", len(features))
	}

	mu.Lock()
	defer mu.Unlock()

	if err := ensureDatasetFile(); err != nil {
		return err
	}

	file, err := os.OpenFile(datasetFilename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open dataset file: %w", err)
	}
	writer := csv.NewWriter(file)
	if err := writer.Write(featuresToStrings(features)); err != nil {
		file.Close()
		return fmt.Errorf("write dataset row: %w", err)
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		file.Close()
		return fmt.Errorf("flush dataset row: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close dataset file: %w", err)
	}
	return nil
}

func ensureDatasetFile() error {
	if info, err := os.Stat(datasetFilename); err == nil {
		if info.Size() > 0 {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat dataset file: %w", err)
	}

	if dir := filepath.Dir(datasetFilename); dir != "." && dir != string(os.PathSeparator) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create dataset dir: %w", err)
		}
	}

	file, err := os.OpenFile(datasetFilename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create dataset file: %w", err)
	}
	writer := csv.NewWriter(file)
	header := []string{"AUTH.Att", "AUTH.Fail", "AUTH.FailMAC", "SM.SessAtt", "SM.SessFail"}
	if err := writer.Write(header); err != nil {
		file.Close()
		return fmt.Errorf("write dataset header: %w", err)
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		file.Close()
		return fmt.Errorf("flush dataset header: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close dataset header file: %w", err)
	}
	return nil
}

func featuresToStrings(features []float64) []string {
	values := make([]string, len(features))
	for i, value := range features {
		values[i] = fmt.Sprintf("%.15g", value)
	}
	return values
}
