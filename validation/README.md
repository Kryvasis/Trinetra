# Accuracy validation contract

Cortex does not ship a claimed accuracy percentage. Software regression tests
show that code behaves consistently; they do not prove that security verdicts
are correct on real networks.

To publish a result, create an independently reviewed JSONL corpus with one
control observation per line. Every record must contain `case_id`, `vendor`,
`os_version`, `control_id`, `expected`, `actual`, `reviewer`, and a
`source_reference`. Supported verdicts are `pass`, `fail`, `manual_review`,
`not_tested`, and `error`. Do not put credentials or raw private configurations
in this repository.

Run:

```bash
python3 tools/measure_accuracy.py /path/to/reviewed-observations.jsonl
```

The tool refuses fewer than 20 observations or a single-vendor dataset. The
generated `validation/results.json` includes the corpus SHA-256, corpus scope,
exact-verdict accuracy, precision, recall, and false-positive/negative rates.
Reviewers should sign and retain the source corpus outside the public repo.

For a judging claim, use a substantially larger corpus, at least three vendors,
multiple OS versions, contradictory/negated commands, partial evidence, and an
expert who did not write the evaluated rules.
