import csv
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

rows = list(csv.DictReader(open('phase2_2_features.csv', encoding='utf-8')))


def build(row, include_roll):
    features = [float(row['auth_attempts']), float(row['auth_failures']), float(row['failure_ratio'])]
    if include_roll:
        features.extend([
            float(row['rolling_mean_ratio']),
            float(row['rolling_max_ratio']),
            float(row['windows_above_soft_thresh']),
            float(row['ratio_slope']),
        ])
    return features

benign = [r for r in rows if r['attack_type'] == 'benign' and r['is_attack'] == 'False']
train = [r for r in benign if int(r['imsi'].split('-')[-1]) <= 10]
train_imsi = {r['imsi'] for r in train}
test_benign = [r for r in benign if r['imsi'] not in train_imsi]
attack = [r for r in rows if r['is_attack'] == 'True' and r['attack_type'] in {'naive_burst', 'paced_evasion'}]
test_attack = [r for r in attack if r['imsi'] not in train_imsi]
test = test_benign + test_attack

X_train = np.array([build(r, False) for r in train], dtype=float)
X_test = np.array([build(r, False) for r in test], dtype=float)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

model = IsolationForest(contamination=0.03, random_state=42)
model.fit(X_train_scaled)
train_scores = model.score_samples(X_train_scaled)
test_scores = model.score_samples(X_test_scaled)
threshold = float(np.percentile(train_scores, 3))
preds = test_scores < threshold

benign_fp = np.mean([p for p, r in zip(preds, test) if r['is_attack'] == 'False'])
naive_detection = np.mean([p for p, r in zip(preds, test) if r['attack_type'] == 'naive_burst'])
paced_detection = np.mean([p for p, r in zip(preds, test) if r['attack_type'] == 'paced_evasion'])

print({'benign_fp': float(benign_fp), 'naive_detection': float(naive_detection), 'paced_detection': float(paced_detection), 'threshold': threshold})
