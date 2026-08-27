# Trinetra Schema

## Session directory layout
```text
sessions/
  <session>/
    <session>.json
    brain_<session>.md
    brain_<session>.bak.md
    brain_state_<session>.json
    artifacts/
```

## Global layout
```text
brain_state.json
stat_scripts/
src/
```

## Session JSON
```json
{
  "session_name": "demo1",
  "target": "example.com",
  "created_at": "ISO-8601",
  "updated_at": "ISO-8601",
  "findings": [
    {
      "finding_id": "uuid-or-deterministic-id",
      "v_code": "V-013",
      "v_name": "Weak password policy",
      "target": "example.com",
      "script": "stat_scripts/V-013.sh",
      "started_at": "ISO-8601",
      "ended_at": "ISO-8601",
      "exit_code": 0,
      "status": "success",
      "raw_output": "...",
      "summary": "...",
      "summary_status": "success|fallback_success|captured_but_unsummarized",
      "summary_model": "nvidia/nemotron-3-ultra-550b-a55b:free",
      "summary_error": null,
      "artifacts": ["artifacts/file1.txt"],
      "tags": ["config", "hardening"]
    }
  ]
}
```

## Session brain state JSON
```json
{
  "session_name": "demo1",
  "target": "example.com",
  "state": "brain_updated",
  "last_updated": "ISO-8601",
  "brain_md_path": "sessions/demo1/brain_demo1.md",
  "brain_backup_path": "sessions/demo1/brain_demo1.bak.md",
  "byte_size": 12345,
  "estimated_tokens": 2800,
  "compression_count": 1,
  "already_run_v_codes": ["V-003", "V-013"],
  "confirmed_findings": ["V-013"],
  "suspected_findings": ["V-006"],
  "counts": {
    "total_runs": 7,
    "success_runs": 6,
    "failed_runs": 1,
    "unsummarized": 1
  },
  "latest_suggestion": {
    "next_v_code": "V-006",
    "reason": "Weak TLS configuration remains untested",
    "confidence": "medium",
    "requires_revalidation": false,
    "based_on": ["tls_surface_present"]
  },
  "suggestion_history": [
    {
      "timestamp": "ISO-8601",
      "next_v_code": "V-006",
      "reason": "Weak TLS configuration remains untested"
    }
  ]
}
```

## Global brain state JSON
```json
{
  "last_updated": "ISO-8601",
  "active_sessions": ["demo1", "demo2"],
  "session_count": 2,
  "high_risk_sessions": ["demo1"],
  "recent_activity": [
    {
      "session": "demo1",
      "timestamp": "ISO-8601",
      "event": "finding_recorded",
      "v_code": "V-013"
    }
  ]
}
```
