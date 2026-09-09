#!/usr/bin/env python3
"""Measure Cortex verdict accuracy from an independently reviewed JSONL corpus.

This tool deliberately refuses tiny or single-vendor datasets so a demo cannot
accidentally publish a misleading percentage as product accuracy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

VERDICTS = {"pass", "fail", "manual_review", "not_tested", "error"}


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def load_records(path: Path) -> list[dict]:
    records = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_number}: invalid JSON ({exc.msg})") from exc
        required = ("case_id", "vendor", "os_version", "control_id", "expected", "actual", "reviewer", "source_reference")
        missing = [field for field in required if not str(item.get(field, "")).strip()]
        if missing:
            raise ValueError(f"line {line_number}: missing {', '.join(missing)}")
        if item["expected"] not in VERDICTS or item["actual"] not in VERDICTS:
            raise ValueError(f"line {line_number}: expected/actual must be a supported Cortex verdict")
        records.append(item)
    return records


def measure(records: list[dict], corpus_sha256: str) -> dict:
    vendors = sorted({str(item["vendor"]).strip() for item in records})
    if len(records) < 20:
        raise ValueError("at least 20 independently reviewed observations are required")
    if len(vendors) < 2:
        raise ValueError("at least two vendors are required for a published multi-vendor result")
    confusion = Counter()
    for item in records:
        expected_fail = item["expected"] == "fail"
        actual_fail = item["actual"] == "fail"
        confusion["tp" if expected_fail and actual_fail else
                  "fn" if expected_fail else
                  "fp" if actual_fail else "tn"] += 1
    correct = sum(item["expected"] == item["actual"] for item in records)
    return {
        "schema": "cortex.validation-result.v1",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "corpus_sha256": corpus_sha256,
        "observations": len(records),
        "vendors": vendors,
        "controls": len({item["control_id"] for item in records}),
        "reviewers": len({item["reviewer"] for item in records}),
        "exact_verdict_accuracy": _ratio(correct, len(records)),
        "fail_detection": {
            "true_positive": confusion["tp"],
            "true_negative": confusion["tn"],
            "false_positive": confusion["fp"],
            "false_negative": confusion["fn"],
            "precision": _ratio(confusion["tp"], confusion["tp"] + confusion["fp"]),
            "recall": _ratio(confusion["tp"], confusion["tp"] + confusion["fn"]),
            "false_positive_rate": _ratio(confusion["fp"], confusion["fp"] + confusion["tn"]),
            "false_negative_rate": _ratio(confusion["fn"], confusion["fn"] + confusion["tp"]),
        },
        "notice": "Metrics describe only the reviewed corpus identified by corpus_sha256; they are not certification.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path, help="Expert-reviewed JSONL observations")
    parser.add_argument("--output", type=Path, default=Path("validation/results.json"))
    args = parser.parse_args()
    payload = args.corpus.read_bytes()
    result = measure(load_records(args.corpus), hashlib.sha256(payload).hexdigest())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
