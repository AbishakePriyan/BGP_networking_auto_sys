"""Poll FRR's BGP RIB, score changed paths, optionally apply a peer-specific filter."""
import argparse
from datetime import datetime, timezone
import json
import time
import joblib
import pandas as pd
from core import ROOT, FEATURES, routes, extract, signature, filter_commands, vty


def emit(event):
    event = {"timestamp": datetime.now(timezone.utc).isoformat(), **event}
    print(json.dumps(event), flush=True)
    (ROOT / "logs").mkdir(exist_ok=True)
    with (ROOT / "logs/events.jsonl").open("a") as file:
        file.write(json.dumps(event) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--auto-mitigate", action="store_true")
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--threshold", type=float, default=0.8)
    args = parser.parse_args()
    if args.interval < 0.2 or not 0 < args.threshold <= 1:
        parser.error("interval must be >=0.2 and threshold must be in (0, 1]")
    bundle = joblib.load(ROOT / "artifacts/model.joblib")
    model = bundle["model"]
    if bundle["features"] != FEATURES:
        raise RuntimeError("Feature schema differs from training. Run train.py again.")
    registry = json.loads((ROOT / "authorized_prefixes.json").read_text())
    attack_index = list(model.classes_).index(1)
    previous = set()
    print("Collector: BGP RIB snapshots, not raw BGP UPDATE capture.", flush=True)
    print("Mode:", "AUTO MITIGATION (isolated lab)" if args.auto_mitigate else "ALERT ONLY", flush=True)
    while True:
        try:
            current_routes = routes()
            current = {signature(route) for route in current_routes}
            for route in current_routes:
                key = signature(route)
                if key in previous:
                    continue
                features = extract(route, registry)
                if features is None:
                    emit({**route, "status": "UNMANAGED", "note": "No authorization baseline"})
                    continue
                risk = float(model.predict_proba(pd.DataFrame([features], columns=FEATURES))[0, attack_index])
                suspicious = risk >= args.threshold
                event = {**route, "risk_score": round(risk, 4), "features": features,
                         "status": "SUSPICIOUS" if suspicious else "NORMAL",
                         "score_note": "Uncalibrated model score, not a verified attack probability"}
                emit(event)
                # Independent lab guardrail. ML alone is not enough for arbitrary auto blocking.
                if suspicious and features["origin_mismatch"] and args.auto_mitigate:
                    started = time.perf_counter()
                    vty("r2", filter_commands(route["peer"], route["prefix"]))
                    verified = False
                    for _ in range(20):
                        time.sleep(0.25)
                        if not any(item["peer"] == route["peer"] and item["prefix"] == route["prefix"]
                                   for item in routes()):
                            verified = True
                            break
                    emit({**event, "status": "MITIGATION_VERIFIED" if verified else "MITIGATION_NOT_VERIFIED",
                          "verification": "Suspicious peer/prefix path absent from accepted BGP RIB",
                          "mitigation_ms": round((time.perf_counter() - started) * 1000, 1)})
            previous = current
        except (RuntimeError, ValueError, OSError) as error:
            emit({"status": "ERROR", "error": str(error)})
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nMonitor stopped. Existing FRR filters remain until reset.")
