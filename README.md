# Cortex

Cortex is a human-governed, multi-vendor network configuration assurance prototype built for SIH problem statement 26155. It collects configuration evidence, preserves vendor and device context, runs deterministic mapped checks, explains findings, and exports assessment reports without converting missing evidence into false confidence.

For a judge in one sentence:

> Cortex turns authorized network configuration evidence into explainable, reviewable findings and locally signed, tamper-evident assessment receipts—with every validation and trust boundary visible.

## Quick start

Prerequisites on Ubuntu or WSL:

- Python 3.10 or newer, including venv support
- JDK 17 or newer
- Node.js 20 or newer with npm installed inside WSL (Windows npm inherited through `/mnt/c` is not compatible with this launcher)
- A C++20 compiler for the optional native probe suite

Start the complete application with one command:

```bash
cd /path/to/Cortex
make start
```

The launcher creates the Python virtual environment when needed, installs changed dependencies, compiles the Java engine, builds the React application, and serves the workspace and API at [http://127.0.0.1:5000](http://127.0.0.1:5000). Press Ctrl+C to stop it.

If port 5000 is already occupied:

```bash
TRINETRA_BRIDGE_PORT=5001 make start
```

`TRINETRA_*` and Java classes beginning with `Trinetra` are legacy internal compatibility identifiers. The product and user interface are Cortex.

## Product workflow

1. Create or reuse an assessment session.
2. Upload one or many sanitized configuration files, or collect from an explicitly authorized target.
3. Detect vendor and OS metadata, normalize supported evidence, and preserve source provenance.
4. Evaluate deterministic checks and keep `pass`, `fail`, `manual_review`, `not_tested`, and `error` distinct.
5. Review explainable findings, framework mappings, evidence gaps, severity, and remediation guidance.
6. Propose recognition rules for unknown syntax. Drafts remain inert until a different reviewer approves them.
7. Compare successive device observations, export reports, and generate a signed integrity receipt after chain verification.
8. Open Assurance to inspect executable coverage, vendor depth, accuracy status, and trust boundaries.

## Architecture

```text
React/Vite workspace
        │ HTTPS/JSON in production
        ▼
Flask validation and orchestration bridge
        │ bounded subprocess calls
        ▼
Java evidence, session, parser, scoring and report engine
        │
        ├── vendor adapters and governed rule map
        ├── append-linked assessment evidence
        └── optional native network probes
```

The repository intentionally preserves one authoritative ingestion and scoring path. File upload and authorized collection converge before evaluation. The LLM narrative and lightweight TF-IDF/KNN suggestion path are advisory; neither can create deterministic compliance scores.

Key locations:

| Area | Location |
| --- | --- |
| React workspace | `frontend/src/` |
| Flask API | `bridge/app.py` |
| Fetch security boundary | `bridge/live_fetcher.py` |
| Java engine | `src/` |
| Vendor adapters | `src/*BaselineAdapter.java` and `src/VendorConnectorRegistry.java` |
| Compliance mappings | `config/compliance_manifest.json` |
| Governed recognition rules | `config/vendor_training_map.json` |
| Live probe scripts | `stat_scripts/` |
| Accuracy contract | `validation/README.md` |
| Trust model | `SECURITY-CLAIMS.md` |

See [ARCHITECTURE.md](ARCHITECTURE.md) for the complete component, data-flow,
governance, integrity and CI diagram.

For presentations, use the simplified one-page
[Cortex architecture PDF](docs/cortex-simple-architecture.pdf).

## Security and trust boundaries

Cortex uses a per-session hash chain to detect changed recorded evidence. After the Java verifier confirms that chain is intact, Cortex can create an Ed25519-signed receipt containing a Merkle root, assessment identifier, count, chain tip, public key, and timestamp.

This proves integrity only inside the stated local assessor trust boundary. It is not an independently operated blockchain transaction. A privileged host administrator can control local files and keys. Cortex therefore does not use the words “immutable,” “blockchain verified,” or “tamper-proof” for the current implementation.

The application also:

- rejects unsafe session/device identifiers and common command-injection characters;
- bounds request bodies and fetched configuration sizes;
- rejects unknown SSH host keys;
- blocks private-address URL collection by default and validates redirects;
- keeps request-scoped credentials out of stored sessions and reports;
- redacts credential-like evidence before serialization;
- omits filesystem paths and executable locations from the health response;
- stores signing material under `.cortex/`, outside version control.

Before shared or public deployment, add authenticated identity, RBAC, tenant isolation, encrypted evidence storage, managed signing keys, rate limiting, job isolation, retention/erasure controls, backups, and an independently operated anchor if the use case requires one. See [SECURITY-CLAIMS.md](SECURITY-CLAIMS.md).

## Capability and accuracy disclosure

The Assurance page derives separate counts for manifest controls, probe scripts, executable verdict implementations, manual-only scripts, and unsupported controls. Vendor detection is never presented as equivalent security depth, and all current vendor rows remain “not production validated.”

Repository regression tests prove repeatable software behavior. They do not prove cybersecurity accuracy. Cortex ships no invented precision or recall percentage.

For an expert-reviewed corpus, follow [validation/README.md](validation/README.md) and run:

```bash
python3 tools/measure_accuracy.py /path/to/reviewed-observations.jsonl
```

The tool refuses fewer than 20 observations and single-vendor datasets. Its output is scoped to the corpus SHA-256 and reports exact-verdict accuracy, precision, recall, false-positive rate, and false-negative rate. A judging claim should use a much larger independently labelled corpus covering at least three vendors, multiple OS versions, contradictory and negated commands, partial evidence, unsupported syntax, and secret-bearing lines.

## Governed training lifecycle

The Training page creates `draft` rules with an author, source reference, confidence, timestamp, version, and history. Drafts are ignored by the Java parser and ML retraining. Activation requires a different reviewer; self-approval is rejected. Review updates are written atomically and active rules remain backward-compatible with legacy entries.

This is a governance baseline, not a complete production control plane. Production activation should additionally run fixture/regression gates, reject semantic pattern conflicts, sign approved rule packs, and use authenticated reviewer identities.

## Assessment history and reports

Sessions retain per-device evidence and expose before/after comparison of the latest observations. Reports are generated from recorded evidence, not from a fresh target scan. Per-device and session PDFs include device metadata, finding class, mapped controls, provenance, and remediation guidance.

The current signed receipt covers recorded chain hashes. PDF-byte signing, QR verification and external ledger anchoring remain future work and are not claimed.

## Verification

Run the full local suites:

```bash
make test
python3 -m pytest bridge/tests -q

cd frontend
npm ci
npm run lint
npm run build
node --test tests/*.mjs
```

CI repeats Java, native, Python and frontend checks, compiles the accuracy tooling, generates Python/npm dependency inventories, uploads a CycloneDX frontend SBOM, and runs CodeQL for Java, JavaScript/TypeScript and Python.

Useful diagnostics:

```bash
curl http://127.0.0.1:5000/api/health
curl http://127.0.0.1:5000/api/assurance/capabilities
make doctor
```

## Primary API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| POST | `/api/session` | Create a session |
| POST | `/api/session/<name>/upload-config` | Ingest uploaded configuration |
| POST | `/api/session/<name>/fetch-config` | Authorized thin collection into the same ingestion path |
| GET | `/api/session/<name>/devices` | List session devices |
| GET | `/api/session/<name>/score` | Deterministic framework score |
| GET | `/api/session/<name>/compare` | Compare recent device observations |
| GET | `/api/session/<name>/audit-report/pdf` | Export session PDF |
| GET | `/api/session/<name>/devices/<device_id>/pdf` | Export per-device PDF |
| POST | `/api/session/<name>/train` | Propose a governed training rule |
| GET | `/api/training-rules?status=draft` | List review queue |
| POST | `/api/training-rules/<rule_id>/review` | Approve or deprecate a rule |
| GET | `/api/session/<name>/integrity-receipt` | Generate locally signed receipt after chain verification |
| POST | `/api/assurance/verify-receipt` | Verify receipt signature and available local evidence |
| GET | `/api/assurance/capabilities` | Publish implementation/validation boundaries |

## Demonstration

Use [DEMO_SCRIPT.md](DEMO_SCRIPT.md) for the judge-facing flow. The strongest four-minute sequence is:

1. Upload a mixed-vendor batch.
2. Open one explainable confirmed risk and its source evidence.
3. Save an unknown command as a draft, show self-approval rejection, then activate it with a second reviewer.
4. Upload a corrected device version and show posture comparison.
5. Generate and verify an integrity receipt.
6. Modify the receipt and show verification fail.
7. Close on Assurance, clearly separating implemented coverage from unmeasured accuracy and external anchoring.

## Current limitations

- No independently labelled production accuracy result is included.
- Vendor semantic depth is uneven and production validation remains outstanding.
- No external ledger anchor is configured.
- Local mode has no multi-user authentication, RBAC or tenant isolation.
- Evidence encryption at rest and managed key storage are not implemented.
- Rule activation does not yet execute a signed fixture gate.
- PDF-byte signatures and QR verification are not implemented.
- Hardware-lab and large-fleet performance results are not included.

These are submission boundaries, not hidden claims. The next credibility milestone is an independently reviewed multi-vendor corpus plus an external verifier operated outside the Cortex host.
