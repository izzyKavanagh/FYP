import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib
from sklearn.metrics import roc_auc_score
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix
from sklearn.metrics import roc_curve

df = pd.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
print(df.shape)

print(df.columns.tolist())
df.columns = df.columns.str.strip()

print(df["Label"].value_counts())

df["Label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

features = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Packet Length Mean",
    "Packet Length Std",
    "SYN Flag Count",
    "FIN Flag Count",
    "ACK Flag Count"
]

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)


X = df[features]
y = df["Label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

rf = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
scores = cross_val_score(rf, X, y, cv=cv, scoring="recall")

print("Mean recall:", scores.mean())


rf.fit(X_train, y_train)

y_pred = rf.predict(X_test)

print(confusion_matrix(y_test, y_pred))
print(classification_report(y_test, y_pred))

cm = confusion_matrix(y_test, y_pred)

plt.figure()
sns.heatmap(cm, annot=True, fmt="d")
plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.title("Confusion Matrix")
plt.show()

y_probs = rf.predict_proba(X_test)[:, 1]

fpr, tpr, thresholds = roc_curve(y_test, y_probs)
roc_auc = roc_auc_score(y_test, y_probs)

plt.figure()
plt.plot(fpr, tpr)
plt.plot([0, 1], [0, 1], linestyle="--")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title(f"ROC Curve (AUC = {roc_auc:.4f})")
plt.show()

importance_df = pd.DataFrame({
    "Feature": features,
    "Importance": rf.feature_importances_
}).sort_values(by="Importance", ascending=True)

plt.figure()
plt.barh(importance_df["Feature"], importance_df["Importance"])
plt.xlabel("Importance")
plt.title("Feature Importance (Random Forest)")
plt.show()

joblib.dump(rf, "rf_model.pkl")

plt.figure()
sns.countplot(x=y)
plt.xticks([0,1], ["Benign", "Malicious"])
plt.title("Class Distribution")
plt.show()

print("ROC AUC:", roc_auc_score(y_test, rf.predict_proba(X_test)[:,1]))

df['Label'].value_counts(normalize=True)

print(confusion_matrix(y_test, y_pred))

y_probs = rf.predict_proba(X_test)[:,1]
print(min(y_probs), max(y_probs))
print(y_probs[:20])

from sklearn.tree import DecisionTreeClassifier

model = DecisionTreeClassifier(max_depth=5)
model.fit(X_train, y_train)
print(model.score(X_test, y_test))

print(X_train.shape, y_train.shape)
print(y_train[:10])
print(df['Label'][:10])