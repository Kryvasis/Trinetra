# Cortex engineering review — 4 September 2026

## Outcome and scope

This is a scoped implementation review of the local upload, assessment evidence,
results/report, Training and System workflows. It is not a penetration-test
certificate, a complete dependency advisory audit, a WCAG certification, or an
assertion that every repository defect is fixed. Existing user evidence and
unrelated worktree changes were preserved. No commit or push was made.

The most serious confirmed problem was evidence accuracy: complete uploaded
configuration text was evaluated using rules intended for live tool output.
Insecure, hardened and incomplete samples could all receive the same unsupported
passes. That is more damaging in a security product than a cosmetic defect.

## Implemented changes

### Evidence correctness and safer reports

- Configuration-only ingestion no longer asserts runtime rule passes or failures.
  These remain manual review until suitable runtime evidence is supplied.
- Added a deliberately narrow Cisco IOS text-observation layer: SSHv1, enabled
  HTTP, Telnet-capable transport, public/private SNMP communities, and supported
  cleartext/weak password directives. Results identify one-based source lines,
  not raw secret values. Comments, supported banners and negated commands are
  excluded. Other vendors are explicitly unsupported by this observation layer.
- Observations are not formal framework-control verdicts. Missing directives
  mean not observed, not secure. The parser is not a full effective-configuration
  evaluator and cannot resolve all hierarchy, overrides or vendor versions.
- Preserved assessment kind, evidence explanation and configuration review in
  normalized hash-chain payloads. Scores expose chain integrity; Results warns
  when verification fails. A regression test tampers with an observation and
  verifies detection.
- Exposed actual per-framework evidence rows instead of empty detail tables.
  Latest configuration observations are selected per active device; aggregate
  verdict counts still describe retained history, clearly labeled.
- Added warnings for legacy configuration-derived evidence. No historical
  verdicts or hashes were retroactively changed: create a fresh assessment and
  reupload configurations to use corrected semantics.
- Removed unverified generic device-changing commands from PDF remediation.
  Guidance now requires evidence validation, vendor/version review, backup,
  rollback and post-change testing. No remediation commands are executed.
- PDF output includes structured configuration observations and does not dump
  raw unrecognized lines. This is not comprehensive redaction or encryption of
  original saved files, Training data, or every possible export.
- Corrupt/unreadable device brain-state data now returns an explicit error
  instead of silently appearing to be an empty device list.

### Frontend workflow and presentation

- Results navigation fetches scores only; generating a PDF is explicit. This
  removes unnecessary report/narrative work from ordinary navigation.
- Framework selection separates draft and applied scope. Download uses applied
  scope, loading prevents duplicate requests, and errors remain visible.
- Added real evidence details with pagination, readable observation disclosures,
  legacy/integrity notices, absent-data states and responsive controls.
- System now auto-loads, searches and paginates saved sessions. Removal/restore
  keeps existing recoverable semantics. Inventory counts use actual saved data;
  configuration presence is no longer advertised as tested AI connectivity.
- Training restores selected-session data, guards stale requests, cleans up
  timeouts, prevents duplicate submissions and explains its empty state.
- Retained the existing graphite design and cinematic introduction. Removed
  progress-width animation and decorative nonzero minimum fill. No dependencies
  or component library were added.

The frontend-design-premium and Impeccable guidance shaped this work around the
existing design contract, meaningful states, restrained motion and bounded
desktop/mobile verification rather than a new visual redesign.

## Verification

- `make compile`: successful; existing unchecked Java warnings remain.
- `.venv/bin/python tests/run_isolated.py`: all 11 Java suites passed;
  109 Python tests passed and one optional PDF text-extraction test skipped.
- `npm run lint`: passed with zero warnings.
- `npm run build`: passed (56 modules; JS 272.45 kB / 84.07 kB gzip).
- `node --test tests/*.mjs` from frontend: five tests passed.
- New regression coverage: configuration-only manual verdicts; source-line
  observations without secret leakage into score/report; comments/banners/
  negation; unsupported vendor; removed device filtering; corrupt-state errors;
  tampered observation integrity detection; PDF bytes generated successfully.
- Browser checks used disposable synthetic sessions, not real saved evidence:
  Results details, draft/applied filters, PDF action, System search/pagination,
  remove/restore, auto-loading and Training empty-state guidance. Desktop and
  390px mobile layouts inspected; sampled mobile document did not overflow.
  Final browser warning/error log was empty. PDF visual pagination was not
  independently rendered during this pass.
- No live external scans, real device configuration changes, or cloud LLM calls
  were needed for these tests. UI verification used a temporary isolated backend.

## Remaining risks and next work

1. **Local-use security boundary:** authentication, per-user authorization,
   isolation, deployment hardening and retention policy need an explicit design
   before public/shared deployment. Do not expose this local backend as-is.
2. **Evidence accuracy breadth:** validate a vendor/version-scoped golden corpus,
   including negative cases and full configuration semantics. Juniper and other
   vendor observation support is not implemented here. Benchmark mappings need
   expert validation; a mapped check does not establish certification.
3. **Sensitive evidence:** original configurations may contain secrets. Establish
   redaction, secure storage, permissions, export consent and verified erasure.
   Remove currently hides/restores data; it does not destroy it.
4. **History semantics:** repeated uploads retain historical verdicts. A separate
   versioned latest-assessment model would make current posture clearer. Validate
   consistency under concurrent assessment/report/mutation workflows.
5. **Training semantics:** recognizing a line is not proving it secure. Review
   mappings and ingestion provenance before automated rule promotion.
6. **Blockchain claim:** the reviewed assessment pipeline demonstrates a local
   tamper-evident hash chain. No independently anchored consensus network was
   demonstrated in this review. A privileged attacker able to rewrite all local
   chain data is a different threat from an accidental edit. Do not market local
   chaining alone as decentralized or immutable blockchain assurance.
7. **Test coverage limits:** no hardware-lab validation, exhaustive accessibility
   audit, comprehensive dependency CVE scan, or verified mobile-device matrix.
   The original demo acceptance script still documents unmet vendor coverage;
   its historical runtime-failure assertion is not the new observation contract.

## Hackathon judge assessment

This is a simulated rigorous university hackathon assessment, not an MIT
affiliation, official score, or prediction of any actual panel's decision.

**Provisional overall: 6/10 — promising demonstrable prototype, not yet a
defensible production security platform.** The problem is useful, the workflow
has substance, and preserving provenance is valuable. The main weaknesses are
validated security accuracy, differentiation, unsupported breadth and an
unclear blockchain trust argument. UI quality helps the demonstration, but
cannot compensate for misleading findings or unsupported claims.

| Criterion | Provisional assessment |
| --- | --- |
| Problem relevance | 8/10: network configuration review is a concrete need |
| Usability/demo clarity | 7/10: coherent local workflow; needs a disciplined story |
| Engineering reliability | 6/10: meaningful regression suite, remaining state/security boundaries |
| Security validity | 5/10: safer uncertainty now, limited validated semantic coverage |
| Novelty/blockchain justification | 4/10: local integrity is useful, external trust advantage unproven |

These are subjective judgments of the inspected scope, not a standardized rubric.

### Highest-value work before judging

1. Pick one defensible promise: explain configuration risks with source evidence
   and traceable remediation review. Demonstrate insecure, improved and incomplete
   inputs, including honest manual-review/unsupported outcomes.
2. Build an expert-reviewed test corpus and publish precision, recall, coverage
   and timing with methodology. Do not invent accuracy or time-savings numbers.
3. Explain the blockchain threat model: who distrusts whom, what is anchored,
   where keys live and what independently detects rewriting. Only add external
   anchoring if it solves the stated problem and fits the problem statement.
4. Show a short reproducible demo: upload → evidence → reviewed correction →
   new assessment → integrity check. Have an offline fallback and disclose what
   was simulated versus run on real authorized hardware.

Questions a demanding judge will ask: Why not an existing configuration auditor?
How do you measure false positives? What exactly does a pass prove? Can a local
administrator rewrite your chain? Why does this need blockchain? Who has tested
it in practice? How are device credentials and uploaded secrets protected?

## Rule-design references

The supported observations are consistent with vendor guidance, but do not
replace device/version-specific configuration review:

- [Cisco IOS XE hardening](https://sec.cloudapps.cisco.com/security/center/resources/IOS_XE_hardening)
- [Cisco SSH configuration guidance](https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-shell-ssh/4145-ssh.html)
- [Cisco command-line password configuration](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-cfg-sec-4cli-0.html)
