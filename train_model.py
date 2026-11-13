import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import shap
import joblib

print("🚀 Generating realistic network flow dataset...")

# Features: ['packet_count', 'byte_count', 'duration_sec', 'pps', 'bps', 'protocol_type']

# 1. NORMAL TRAFFIC (Interactive, Web, DNS + Heavy Downloads)
n_normal = 800
# Thoda overlap add kiya (high bound ko 600 kar diya)
norm_pkt = np.random.uniform(1, 600, n_normal)
norm_dur = np.random.uniform(0.5, 15.0, n_normal)
norm_byte = norm_pkt * np.random.uniform(64, 1000, n_normal)
norm_pps = norm_pkt / norm_dur
norm_bps = norm_byte / norm_dur
norm_proto = np.random.choice([1, 6, 17], n_normal)
X_normal = np.column_stack([norm_pkt, norm_byte, norm_dur, norm_pps, norm_bps, norm_proto])
y_normal = np.zeros(n_normal)

# 2. ATTACK TRAFFIC (ICMP Floods, TCP SYN Floods + Low-rate slow attacks)
n_attack = 800
# Attack ko bhi thoda overlap kiya (low bound ko 400 kar diya)
att_pkt = np.random.uniform(400, 5000, n_attack)
att_dur = np.random.uniform(0.1, 3.0, n_attack)
att_byte = att_pkt * np.random.uniform(64, 1500, n_attack)
att_pps = att_pkt / att_dur
att_bps = att_byte / att_dur
att_proto = np.random.choice([1, 6, 17], n_attack)
X_attack = np.column_stack([att_pkt, att_byte, att_dur, att_pps, att_bps, att_proto])
y_attack = np.ones(n_attack)

# Combine and prepare dataset
X = np.vstack([X_normal, X_attack])
y = np.concatenate([y_normal, y_attack])
features = ['packet_count', 'byte_count', 'duration_sec', 'pps', 'bps', 'protocol_type']
df = pd.DataFrame(X, columns=features)

# Train-Test Split for academic validation
X_train, X_test, y_train, y_test = train_test_split(df, y, test_size=0.2, random_state=42)

print("🧠 Training Random Forest Classifier...")
model = RandomForestClassifier(n_estimators=25, max_depth=6, random_state=42)
model.fit(X_train, y_train)

# Model Evaluation Metrics (Show this to examiner!)
y_pred = model.predict(X_test)
print("\n" + "="*40)
print("📊 MODEL EVALUATION METRICS (TEST SET)")
print("="*40)
print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Normal (0)', 'Attack (1)']))
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))
print("="*40 + "\n")

# Save model & explainer
explainer = shap.TreeExplainer(model)
joblib.dump(model, 'rf_model.pkl')
joblib.dump(explainer, 'shap_explainer.pkl')
print("✅ Upgraded model with PPS/BPS features saved successfully!")