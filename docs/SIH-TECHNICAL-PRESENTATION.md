# Cortex SIH technical presentation

Use exactly five slides. Keep screenshots large and record all claims from a
fresh assessment created with the synthetic test pack.

## Slide 1: Problem and product

**Cortex**

Network teams receive configuration exports in incompatible vendor syntax.
Cortex converts authorized configuration evidence into a shared security
baseline, evaluates mapped controls, and produces reviewable per-device reports.

Visible disclosure: SIH Problem Statement 26155 prototype. Configuration
assessment, not compliance certification.

## Slide 2: Architecture

Show `docs/cortex-simple-architecture.pdf` or its source diagram.

Flow: React workspace to Flask bridge to vendor adapters and governed training,
then deterministic controls, framework mappings, hash-chained evidence, and PDF
reports. Optional Gemini and local KNN suggestions remain advisory. They never
override deterministic verdicts.

## Slide 3: Multi-vendor evidence

Use one Results screenshot containing Cisco, Juniper, and FortiOS devices.

- Hardened, insecure, incomplete, and conflicting-command fixtures exist for
  all three demonstrated vendors.
- Every upload accounts for all 28 manifest controls.
- Each result states whether configuration semantics, live evidence, or another
  assessment type is required.
- CIS, NIST SP 800-53, DISA STIG, and ISO/IEC 27001 mappings are selectable.

## Slide 4: Governed learning and integrity

Use one Training screenshot and one Assurance screenshot.

An operator maps unknown syntax to an allowlisted normalized field. A different
reviewer activates the draft only after positive and negative regression cases
pass. Every upload receives an assessment ID and configuration SHA-256. Cortex
stores hash-chained results, an immutable snapshot, and a locally signed
Ed25519 receipt.

## Slide 5: Demonstrated results and limits

Show only measurements reproduced for the submitted commit:

- 290 Python tests passed and one skipped in the isolated full-suite run.
- Java suites and C++ probe tests passed.
- 21 semantic fixture assertions cover three vendors.
- React lint and production build passed.

Current boundaries: no claim of full framework certification, universal vendor
support, independently measured model accuracy, production RBAC, or external
blockchain anchoring. Next production work covers independent lab validation,
multi-user storage, worker queues, and deployment monitoring.
