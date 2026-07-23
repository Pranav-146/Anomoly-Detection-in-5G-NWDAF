package dataset

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func withTempDataset(t *testing.T) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	return dir, func() {
		_ = os.Chdir(oldWD)
	}
}

func TestAppendFeatureVectorWritesHeaderOnceAndFiveValues(t *testing.T) {
	_, cleanup := withTempDataset(t)
	defer cleanup()

	if err := AppendFeatureVector([]float64{1, 2, 3, 4, 5}); err != nil {
		t.Fatalf("AppendFeatureVector returned error: %v", err)
	}
	if err := AppendFeatureVector([]float64{6, 7, 8, 9, 10}); err != nil {
		t.Fatalf("second append returned error: %v", err)
	}

	path := filepath.Join(".", "nwdaf_feature_dataset.csv")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read dataset: %v", err)
	}

	rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows (header + 2 data rows), got %d", len(rows))
	}
	if len(rows[0]) != 5 || len(rows[1]) != 5 || len(rows[2]) != 5 {
		t.Fatalf("expected 5 values per row, got %#v", rows)
	}
}

func TestAppendFeatureVectorRejectsWrongFeatureCount(t *testing.T) {
	_, cleanup := withTempDataset(t)
	defer cleanup()

	if err := AppendFeatureVector([]float64{1, 2, 3}); err == nil {
		t.Fatal("expected error for wrong number of features")
	}
}

func TestAppendFeatureVectorConcurrentAppendsRemainValid(t *testing.T) {
	_, cleanup := withTempDataset(t)
	defer cleanup()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = AppendFeatureVector([]float64{float64(i), float64(i + 1), float64(i + 2), float64(i + 3), float64(i + 4)})
		}(i)
	}
	wg.Wait()

	rows, err := csv.NewReader(strings.NewReader(readFileString(t, "nwdaf_feature_dataset.csv"))).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(rows) != 11 {
		t.Fatalf("expected 11 rows after concurrent appends, got %d", len(rows))
	}
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
