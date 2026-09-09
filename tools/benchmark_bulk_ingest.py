#!/usr/bin/env python3
"""Measure Cortex API ingestion throughput against a running local backend.

This is an engineering benchmark, not a capacity claim. It creates one isolated
session and unique device IDs, then submits the same synthetic fixture N times.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import statistics
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path


def request_json(url: str, method: str = "GET", payload: dict | None = None) -> tuple[int, dict]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=180) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8"))
        except Exception:
            detail = {"error": str(exc)}
        return exc.code, detail


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * fraction)))
    return ordered[index]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--fixture", type=Path, default=Path("demo/security-test-pack/cisco-hardened-excerpt.txt"))
    parser.add_argument("--count", type=int, default=25)
    parser.add_argument("--concurrency", type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.count <= 5000 or not 1 <= args.concurrency <= 32:
        parser.error("count must be 1-5000 and concurrency must be 1-32")

    config = args.fixture.read_text(encoding="utf-8")
    session = f"benchmark-{uuid.uuid4().hex[:10]}"
    base = args.base_url.rstrip("/")
    status, response = request_json(f"{base}/api/session", "POST", {"name": session, "target": "bulk-ingest-benchmark"})
    if status != 201:
        raise SystemExit(f"session creation failed ({status}): {response}")

    def ingest(index: int) -> dict:
        started = time.perf_counter()
        code, result = request_json(f"{base}/api/session/{session}/upload-config", "POST", {
            "device_id": f"benchmark-device-{index:03d}",
            "vendor": "auto",
            "filename": args.fixture.name,
            "config_content": config,
        })
        return {"status": code, "seconds": time.perf_counter() - started, "error": result.get("error")}

    wall_started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        results = list(pool.map(ingest, range(1, args.count + 1)))
    wall = time.perf_counter() - wall_started
    latencies = [item["seconds"] for item in results]
    successful = sum(item["status"] == 200 for item in results)
    output = {
        "schema": "cortex.bulk-benchmark.v1",
        "session": session,
        "fixture": str(args.fixture),
        "requests": args.count,
        "concurrency": args.concurrency,
        "successful": successful,
        "failed": args.count - successful,
        "wall_seconds": round(wall, 3),
        "throughput_per_second": round(successful / wall, 3) if wall else None,
        "latency_seconds": {
            "mean": round(statistics.mean(latencies), 3),
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "max": round(max(latencies), 3),
        },
        "notice": "Local synthetic workload only; retain the session as reproducible evidence or remove it through System Health.",
    }
    print(json.dumps(output, indent=2))
    return 0 if successful == args.count else 1


if __name__ == "__main__":
    raise SystemExit(main())
