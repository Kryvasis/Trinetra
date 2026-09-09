"""Evidence assurance helpers for Cortex.

Signed local receipts are kept distinct from independently anchored blockchain
proof. The API never claims an external anchor unless one actually exists.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _merkle_root(values: list[str]) -> str:
    if not values:
        return hashlib.sha256(b"CORTEX_EMPTY_ASSESSMENT").hexdigest()
    level = [hashlib.sha256(value.encode("ascii", "ignore")).digest() for value in values]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def _key_path(root: str) -> Path:
    configured = os.environ.get("CORTEX_SIGNING_KEY_FILE", "").strip()
    return Path(configured) if configured else Path(root) / ".cortex" / "assessment_ed25519.pem"


def _load_or_create_key(root: str) -> Ed25519PrivateKey:
    path = _key_path(root)
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    payload = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
    return key


def build_receipt(root: str, session: str, brain: dict[str, Any], *, chain_verified: bool = False) -> dict[str, Any]:
    entries = [item for item in brain.get("normalized_results", []) if isinstance(item, dict)]
    chain_hashes = [str(item.get("chain_hash")) for item in entries if item.get("chain_hash")]
    key = _load_or_create_key(root)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    body = {
        "schema": "cortex.integrity-receipt.v1",
        "assessment_id": f"{session}:{len(entries)}:{_merkle_root(chain_hashes)[:16]}",
        "session": session,
        "entry_count": len(entries),
        "chain_tip": chain_hashes[-1] if chain_hashes else None,
        "merkle_root": _merkle_root(chain_hashes),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "signature_algorithm": "Ed25519",
        "public_key": base64.b64encode(public).decode("ascii"),
        "trust_scope": "local_assessor_signature",
        "chain_verified_before_signing": chain_verified,
        "external_anchor": None,
        "trust_notice": "Verifies this receipt against its embedded public key. No independently operated ledger anchor is configured.",
    }
    body["signature"] = base64.b64encode(key.sign(_canonical(body))).decode("ascii")
    return body


def verify_receipt(receipt: dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(receipt, dict) or receipt.get("schema") != "cortex.integrity-receipt.v1":
        return False, "Unsupported or missing receipt schema."
    signature = receipt.get("signature")
    public_key = receipt.get("public_key")
    if not isinstance(signature, str) or not isinstance(public_key, str):
        return False, "Receipt signature or public key is missing."
    body = dict(receipt)
    body.pop("signature", None)
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True)).verify(
            base64.b64decode(signature, validate=True), _canonical(body)
        )
    except Exception:
        return False, "Signature verification failed. The receipt was altered or is malformed."
    return True, "Signature is valid for the embedded assessor public key."


def capability_report(root: str) -> dict[str, Any]:
    base = Path(root)
    manifest = json.loads((base / "config" / "compliance_manifest.json").read_text(encoding="utf-8"))
    controls = sorted(key for key in manifest if key.startswith("V-"))
    scripts = {path.stem: path for path in (base / "stat_scripts").glob("V-*.sh")}
    in_scope = [control for control in controls if control in scripts]
    manual = []
    for control in in_scope:
        script = scripts[control].read_text(encoding="utf-8", errors="replace").lower()
        if "verdict: manual_review" in script and "verdict: pass" not in script and "verdict: fail" not in script:
            manual.append(control)
    automated = [control for control in in_scope if control not in manual]
    frameworks = sorted({name for control in controls for name in (manifest[control].get("frameworks") or {})})
    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "manifest_controls": len(controls),
        "probe_scripts": len(scripts),
        "controls_with_probe_scripts": len(in_scope),
        "automated_probe_implementations": len(automated),
        "manual_review_only": len(manual),
        "controls_without_probe_script": len([control for control in controls if control not in scripts]),
        "frameworks": frameworks,
        "manual_review_controls": manual,
        "vendors": [
            {"vendor": "Cisco IOS XE", "semantic_depth": "extended", "validation": "repository regression suite", "production_validated": False},
            {"vendor": "Juniper JunOS", "semantic_depth": "baseline", "validation": "repository regression suite", "production_validated": False},
            {"vendor": "FortiOS", "semantic_depth": "baseline", "validation": "synthetic fixtures", "production_validated": False},
            {"vendor": "PAN-OS", "semantic_depth": "baseline", "validation": "synthetic fixtures", "production_validated": False},
            {"vendor": "SONiC / AWS / Generic", "semantic_depth": "experimental", "validation": "not independently validated", "production_validated": False},
        ],
        "accuracy": {
            "status": "not_independently_measured",
            "precision": None,
            "recall": None,
            "false_positive_rate": None,
            "measurement_harness": "tools/measure_accuracy.py",
            "validation_contract": "validation/README.md",
            "notice": "Repository tests verify behavior, not expert-labelled cybersecurity accuracy. No accuracy percentage is claimed.",
        },
        "claims": {
            "scoring": "Deterministic mapped-check pass rate; not certification.",
            "ai": "Advisory suggestions require human review; deterministic rules remain authoritative.",
            "integrity": "Local hash chain and local Ed25519 receipt; not independently anchored blockchain proof.",
        },
    }
