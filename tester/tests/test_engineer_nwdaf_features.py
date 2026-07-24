import csv
import importlib.util
from pathlib import Path


def load_module():
    module_path = Path(__file__).resolve().parents[1] / "tools" / "engineer_nwdaf_features.py"
    spec = importlib.util.spec_from_file_location("engineer_nwdaf_features", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_imsi_level_split_is_stratified_and_grouped(tmp_path):
    module = load_module()
    input_path = tmp_path / "input.csv"
    output_path = tmp_path / "output.csv"

    rows = []
    for imsi, attack_type, ratio in [
        ("IMSI001", "naive_attacker", 0.40),
        ("IMSI002", "naive_attacker", 0.30),
        ("IMSI003", "paced_evasion", 0.29),
        ("IMSI004", "paced_evasion", 0.30),
        ("IMSI005", "benign", 0.02),
        ("IMSI006", "benign", 0.03),
    ]:
        for idx in range(3):
            rows.append(
                {
                    "timestamp_unix": str(1000 + idx),
                    "imsi": imsi,
                    "attack_type": attack_type,
                    "failure_ratio": f"{ratio:.2f}",
                    "window_index": str(idx),
                }
            )

    with input_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    module.engineer_features(input_path, output_path, lookback=3, test_size=0.5)

    with output_path.open("r", encoding="utf-8", newline="") as fh:
        written_rows = list(csv.DictReader(fh))

    assert written_rows, "expected at least one output row"
    assert {row["data_split"] for row in written_rows} == {"train", "test"}

    campaigns = {(row["imsi"], row["attack_type"]) for row in written_rows}
    for campaign in campaigns:
        split_values = {row["data_split"] for row in written_rows if (row["imsi"], row["attack_type"]) == campaign}
        assert len(split_values) == 1, f"campaign {campaign} should stay in one split"

    train_rows = [row for row in written_rows if row["data_split"] == "train"]
    test_rows = [row for row in written_rows if row["data_split"] == "test"]
    assert train_rows and test_rows

    train_attack_types = {row["attack_type"] for row in train_rows}
    test_attack_types = {row["attack_type"] for row in test_rows}
    assert train_attack_types & test_attack_types, "expected attack types to be present in both splits"
