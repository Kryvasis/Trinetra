import { useState, useEffect, useRef } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import Spinner from '../components/Spinner'
import SceneHeader from '../components/SceneHeader'
import { rememberSession, validSession } from '../utils/activeSession'

const FRAMEWORKS = ['CIS', 'ISO27001', 'NIST_800-53', 'STIG', 'PCI-DSS', 'SOC2']
const format = value => String(value || '').replace(/_/g, ' ')
// Mirror of TrinetraConfigIngestor Category 2 (requires live verification).
const CAT2 = new Set(['V-005', 'V-007', 'V-008', 'V-070', 'V-087', 'V-105', 'V-106', 'V-144'])
const findingClass = row => {
  if (row.finding_class) return row.finding_class
  const tid = String(row.test_id || '').toUpperCase()
  if (tid === 'UNRECOGNIZED' || row.result === 'error' || row.result === 'not_tested' || CAT2.has(tid)) return 'unsupported check'
  if (row.result === 'pass') return 'verified pass'
  if (row.result === 'fail') return 'confirmed risk'
  return 'insufficient evidence'
}
const classBadge = cls => cls === 'confirmed risk' ? 'fail' : cls === 'verified pass' ? 'pass' : 'review'

export default function ResultsView({ api, toast }) {
  const [params] = useSearchParams()
  const requested = params.get('session') || ''
  const [input, setInput] = useState(requested)
  const [score, setScore] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState(FRAMEWORKS)
  const [applied, setApplied] = useState(FRAMEWORKS)
  const [active, setActive] = useState('')
  const [page, setPage] = useState(0)
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState('')
  const requestRef = useRef(null)
  const exportRef = useRef(null)
  const loadRef = useRef(null)
  const loadedRef = useRef('')
  const sessionRef = useRef(null)
  useEffect(() => () => {
    requestRef.current?.abort(); requestRef.current = null
    exportRef.current?.abort(); exportRef.current = null
  }, [])

  async function load(event, name = input.trim()) {
    event?.preventDefault()
    if (exportRef.current) return
    if (!validSession(name)) { setError('Use 1–64 letters, numbers, hyphens or underscores.'); sessionRef.current?.focus(); return }
    requestRef.current?.abort()
    const controller = new AbortController()
    requestRef.current = controller
    const scope = [...selected]
    setLoading(true); setError(''); setExportError('')
    if (name !== loadedRef.current) setScore(null)
    const timeout = setTimeout(() => controller.abort(), 60000)
    try {
      const response = await fetch(`${api}/session/${encodeURIComponent(name)}/score?frameworks=${encodeURIComponent(scope.join(','))}`, {signal: controller.signal})
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || `Results unavailable (${response.status})`)
      if (requestRef.current !== controller) return
      const next = data.score || data
      if (!next.frameworks || typeof next.frameworks !== 'object' || Array.isArray(next.frameworks)) throw new Error('The results response is incomplete. Retry or check System diagnostics.')
      setScore(next); setApplied(scope); setActive(Object.keys(next.frameworks || {})[0] || ''); setPage(0)
      loadedRef.current = name; setInput(name); rememberSession(name)
      toast('Results loaded', 'success')
    } catch (err) {
      if (requestRef.current === controller) setError(err.name === 'AbortError' ? 'Results timed out. Check the backend and retry.' : err.message)
    } finally {
      clearTimeout(timeout)
      if (requestRef.current === controller) { requestRef.current = null; setLoading(false) }
    }
  }
  useEffect(() => { loadRef.current = load })
  useEffect(() => {
    exportRef.current?.abort(); exportRef.current = null; setExporting(false)
    if (requested && requested !== loadedRef.current) { setInput(requested); loadRef.current(null, requested) }
  }, [requested])

  async function download() {
    if (exportRef.current || requestRef.current || !score) return
    const exportSession = loadedRef.current
    const controller = new AbortController()
    exportRef.current = controller; setExporting(true); setExportError('')
    const timeout = setTimeout(() => controller.abort(), 130000)
    try {
      const response = await fetch(`${api}/session/${encodeURIComponent(exportSession)}/audit-report/pdf?frameworks=${encodeURIComponent(applied.join(','))}`, {signal: controller.signal})
      if (!response.ok) { const data = await response.json().catch(() => ({})); throw new Error(data.error || `Export failed (${response.status})`) }
      const blob = await response.blob()
      if (exportRef.current !== controller) return
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a'); link.href = url; link.download = `audit_report_${exportSession}.pdf`; link.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
      toast('Report downloaded', 'success')
    } catch (err) {
      if (exportRef.current === controller) setExportError(err.name === 'AbortError' ? 'Export timed out; your results are still available. Retry after checking the backend.' : err.message)
    } finally {
      clearTimeout(timeout)
      if (exportRef.current === controller) { exportRef.current = null; setExporting(false) }
    }
  }
  const fw = score?.frameworks?.[active]
  const rows = fw?.results || []
  const dirty = selected.join(',') !== applied.join(',')
  const rate = data => data?.total_tests_mapped > 0 ? `${data.compliance_percentage}%` : '—'
  return <div>
    <SceneHeader title="Results & evidence" description="Review what the evidence supports, what needs verification, and the next steps. Mapped-check pass rates are not compliance certifications." />
    <section className="benchmark-panel" aria-labelledby="benchmark-heading">
      <div className="benchmark-heading-row"><h2 id="benchmark-heading">Assessment frameworks</h2><span>{selected.length} selected</span></div>
      <div className="benchmark-grid">{FRAMEWORKS.map(name => <label className={`benchmark-option${selected.includes(name) ? ' is-selected' : ''}`} key={name}>
        <input type="checkbox" checked={selected.includes(name)} disabled={loading || exporting || (selected.length === 1 && selected.includes(name))} onChange={() => setSelected(current => FRAMEWORKS.filter(item => item === name ? !current.includes(item) : current.includes(item)))} />
        <span className="choice-control" aria-hidden="true" /><span className="benchmark-name">{format(name)}</span>
      </label>)}</div>
      <p className="benchmark-help">Keep at least one selected. Load results to apply changes. PDF exports use the displayed scope.</p>
    </section>
    <form onSubmit={load} noValidate className="assessment-toolbar results-session-toolbar">
      <label htmlFor="results-session">Saved session</label><input ref={sessionRef} id="results-session" value={input} maxLength={64} onChange={event => setInput(event.target.value)} disabled={loading || exporting} aria-invalid={!!error && !validSession(input.trim())} aria-describedby={error ? 'results-error' : undefined} />
      <button className="btn-primary" disabled={loading || exporting || !input.trim()}>{loading ? <><Spinner size={14} /> Loading results…</> : 'Load results'}</button>
    </form>
    {loading && <p role="status" className="field-help">{score ? 'Refreshing assessment. The previous results remain visible until the request completes.' : 'Loading assessment evidence…'}</p>}
    {error && <div className="card" role="alert" id="results-error"><h2>{score ? 'Could not refresh results' : 'Results unavailable'}</h2><p>{error}</p>{score && <p>The previously loaded assessment remains below.</p>}<button className="btn-secondary" onClick={load} disabled={loading || exporting}>Retry</button></div>}
    {!score && !loading && !error && <div className="empty-state card"><h2>No assessment selected</h2><p>Upload a configuration or open a saved session to review its evidence.</p><Link className="btn-secondary" to="/upload">Upload & collect</Link></div>}
    {score && <>
      <div className="assessment-summary result-session-summary"><div><span>Assessment session</span><h2>{loadedRef.current}</h2></div><div className="result-summary-meta"><span>{score.total_tests_executed ?? 0} recorded checks</span><time dateTime={score.generated_at || undefined}>{score.generated_at ? new Date(score.generated_at).toLocaleString() : 'Time not recorded'}</time></div></div>
      {dirty && <p role="status" className="assessment-notice">Framework selection changed. Load results to apply it; results and PDF still use the displayed scope.</p>}
      {score.legacy_config_records > 0 && <p className="assessment-notice">This session contains {score.legacy_config_records} older configuration records. Their historical verdicts have not been corrected. Create a fresh assessment and re-upload to use the current evidence rules.</p>}
      <p className="field-help">{score.history_basis}</p>
      {score.evidence_chain_intact === false && <p role="alert" className="assessment-notice">Evidence integrity check failed: {score.evidence_chain_detail}. Treat these historical records as untrusted; do not use this report as verified evidence.</p>}
      {(score.configuration_reviews || []).length > 0 && <section className="card" aria-labelledby="config-review-heading">
        <h2 id="config-review-heading">Configuration observations</h2><p>Explicit directives in supplied text—not proof that a service is reachable. “Not observed” is not a pass and does not affect benchmark scores.</p>
        {score.configuration_reviews.map(review => <details className="evidence-disclosure" key={review.device_id}>
          <summary>{review.device_id} — {review.parser === 'unsupported' ? 'Parser not supported' : `${review.observations.filter(item => item.status === 'observed_risk').length} risky directive types observed`}</summary>
          <p>{review.scope}</p>{review.observations.map(item => <div className="observation-row" key={item.id}><div><strong>{item.title}</strong><span className={`badge ${item.status === 'observed_risk' ? 'badge-fail' : 'badge-review'}`}>{format(item.status)}</span></div>{item.line_numbers.length > 0 && <p>Source lines: {item.line_numbers.join(', ')}</p>}<p>{item.next_step}</p></div>)}
        </details>)}
      </section>}
      <section className="card" aria-labelledby="mapped-heading">
        <h2 id="mapped-heading">Mapped-check outcomes</h2><p className="field-help result-scope-help">Each result is classified as a confirmed risk, verified pass, insufficient evidence, or unsupported check. Cisco IOS currently has the complete observation layer; other vendors may require manual verification.</p><div className="framework-tabs" aria-label="Assessment framework">{Object.entries(score.frameworks || {}).map(([name, data]) => <button type="button" key={name} className={`framework-tab ${active === name ? 'active' : ''}`} aria-pressed={active === name} onClick={() => {setActive(name); setPage(0)}}><span>{format(name)}</span><strong>{rate(data)}</strong></button>)}</div>
        {fw && <><div className="assessment-summary framework-summary"><h3>{format(active)}</h3><span>{rate(fw)} mapped-check pass rate</span></div><dl className="outcome-counts"><div><dt>Passed</dt><dd>{fw.tests_passed}</dd></div><div><dt>Failed</dt><dd>{fw.tests_failed}</dd></div><div><dt>Manual review</dt><dd>{fw.tests_manual_review}</dd></div><div><dt>Errors</dt><dd>{fw.tests_errors}</dd></div><div><dt>Not tested</dt><dd>{fw.tests_not_tested}</dd></div></dl>
          {fw.total_tests_mapped === 0 && <p>No recorded checks map to this framework. No pass rate can be established.</p>}
          {rows.length > 0 && <><div className="table-wrap evidence-table-wrap" tabIndex={0} role="region" aria-label={`${format(active)} evidence findings`}><table className="evidence-table"><caption className="sr-only">Mapped checks and evidence for {format(active)}</caption><thead><tr><th scope="col">Device / check</th><th scope="col">Finding class</th><th scope="col">Evidence / next step</th></tr></thead><tbody>{rows.slice(page * 20, (page + 1) * 20).map((row, index) => <tr key={`${row.device_id}-${row.test_id}-${index}`}><td><strong className="result-device">{row.device_id}</strong><code className="result-check">{row.test_id}</code><small>Raw verdict · {format(row.result)}</small></td><td><span className={`badge badge-${classBadge(findingClass(row))}`}>{findingClass(row)}</span>{(row.evidence_lines || []).length > 0 && <small className="evidence-controls">Source · {(row.evidence_lines || []).slice(0, 3).join(' | ')}</small>}</td><td><p className="result-remediation">{row.remediation}</p><small className="evidence-controls">Mapped controls · {(row.controls || []).length ? row.controls.join(', ') : 'None recorded'}</small></td></tr>)}</tbody></table></div><div className="assessment-pagination" aria-label="Evidence pages"><span role="status">{page * 20 + 1}–{Math.min((page + 1) * 20, rows.length)} of {rows.length}</span><button type="button" className="btn-secondary" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button><button type="button" className="btn-secondary" disabled={(page + 1) * 20 >= rows.length} onClick={() => setPage(page + 1)}>Next</button></div></>}
        </>}
      </section>
      <section className="report-actions"><h2>Export assessment</h2><p>Generates a fresh report for the displayed frameworks. Existing AI integration may be used if configured. Avoid changing session evidence during export.</p><button className="btn-primary" onClick={download} disabled={exporting || loading}>{exporting ? <><Spinner size={14} /> Generating PDF…</> : 'Download PDF report'}</button>{exportError && <p role="alert">{exportError}</p>}</section>
    </>}
  </div>
}
