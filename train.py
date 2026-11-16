"""Train on synthetic scenarios. These metrics do NOT establish real-world accuracy."""
import json
import random
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from core import ROOT, FEATURES


def main():
    rng = random.Random(42)
    rows = []
    for label in [0, 1]:
        for _ in range(1200):
            delta = rng.choice([0, 0, 0, 1, 2, 3, 4])
            length = rng.randint(1, 8)
            rows.append({"origin_mismatch": label, "is_more_specific": int(delta > 0),
                         "prefix_length_delta": delta, "as_path_length": length,
                         "repeated_as_count": rng.randint(0, min(3, length - 1)),
                         "label": label})
    frame = pd.DataFrame(rows)
    train_x, test_x, train_y, test_y = train_test_split(
        frame[FEATURES], frame["label"], test_size=0.25, random_state=42,
        stratify=frame["label"])
    model = RandomForestClassifier(n_estimators=150, max_depth=8,
                                   class_weight="balanced", random_state=42, n_jobs=-1)
    model.fit(train_x, train_y)
    prediction = model.predict(test_x)
    report = classification_report(test_y, prediction, output_dict=True, zero_division=0)
    report["confusion_matrix"] = confusion_matrix(test_y, prediction).tolist()
    report["data_source"] = "Synthetic ownership-mismatch scenarios only"
    report["limitation"] = ("Labels are generated from origin_mismatch, so this is a pipeline "
                            "demonstration. A registry rule can solve this demo directly. "
                            "These scores do not show an advantage over rules or performance "
                            "on real BGP hijacks. Train and evaluate on independent events "
                            "before making those claims.")
    (ROOT / "data").mkdir(exist_ok=True)
    (ROOT / "artifacts").mkdir(exist_ok=True)
    frame.to_csv(ROOT / "data/synthetic_training.csv", index=False)
    joblib.dump({"model": model, "features": FEATURES,
                 "training_source": report["data_source"]}, ROOT / "artifacts/model.joblib")
    (ROOT / "artifacts/metrics.json").write_text(json.dumps(report, indent=2))
    print(classification_report(test_y, prediction, zero_division=0))
    print("Confusion matrix:", report["confusion_matrix"])
    print("Saved artifacts/model.joblib and artifacts/metrics.json")
    print("LIMITATION:", report["limitation"])


if __name__ == "__main__":
    main()
