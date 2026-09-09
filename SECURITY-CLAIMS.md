# Cortex security and trust claims

## What Cortex proves

- Recorded evidence is linked by the existing per-session hash chain.
- A generated integrity receipt commits to the recorded chain hashes with a Merkle root.
- The receipt is signed with an Ed25519 assessor key stored outside version control.
- The verification endpoint detects a changed receipt and can compare it with the currently stored session evidence.

## What Cortex does not prove

- A local signature is not an independently anchored blockchain transaction.
- A mapped-check pass rate is not a compliance certification.
- Repository regression tests are not an expert-labelled accuracy study.
- Recognizing vendor syntax does not prove a configuration is safe or effective.
- An operator with control of the application host remains inside the local trust boundary.

The Assurance page exposes these boundaries directly. An external ledger integration may populate `external_anchor` only when a receipt is actually committed to an independently operated system. Configuration contents, credentials and raw evidence must never be placed on a ledger.

## Threat model

| Actor | Trust assumption | Current protection |
| --- | --- | --- |
| Network operator | Authorized to submit sanitized configuration evidence | Explicit collection controls and request-scoped credentials |
| Rule author | May propose parsing knowledge but cannot self-approve a governed draft | Draft → independent approval lifecycle |
| Rule reviewer | Accountable for activating a rule | Reviewer identity, timestamp, version and history in the rule record |
| Local host administrator | Controls local files and execution | Trusted in the current local deployment; no claim of resistance |
| External auditor | Receives reports and receipts | Can verify receipt signature; independent ledger trust is not yet configured |

## Production prerequisites

Before shared or public deployment, add authenticated identities, RBAC, tenant isolation, encrypted evidence storage, managed signing keys, rate limiting, bounded job execution, retention/erasure policy, frozen report snapshots and an independently operated anchor where required.
