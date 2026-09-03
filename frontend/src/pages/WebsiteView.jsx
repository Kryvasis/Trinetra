import { useEffect, useRef, useState } from 'react'
import Spinner from '../components/Spinner'

const LABELS = { pass: 'Passed check', fail: 'Failed check', manual_review: 'Manual review', not_tested: 'Not tested' }

export default function WebsiteView({ api, toast, onBusyChange }) {
  const [url, setUrl] = useState('')
  const [acknowledged, setAcknowledged] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [fieldError, setFieldError] = useState(false)
  const [busy, setBusy] = useState(false)
  const [exporting, setExporting] = useState(false)
  const controller = useRef(null)
  const downloadController = useRef(null)
  const input = useRef(null)
  const consent = useRef(null)

  useEffect(() => {
    onBusyChange?.(busy || exporting)
    return () => onBusyChange?.(false)
  }, [busy, exporting, onBusyChange])

  useEffect(() => () => {
    controller.current?.abort()
    downloadController.current?.abort()
  }, [])

  async function analyze(event) {
    event.preventDefault()
    if (controller.current) return
    setError('')
    setFieldError(false)
    try {
      const parsed = new URL(url.trim())
      if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.port || url.length > 2048) throw new Error()
    } catch {
      setError('Enter a public HTTP or HTTPS URL without credentials or a custom port.')
      setFieldError(true)
      input.current?.focus()
      return
    }
    if (!acknowledged) {
      setError('Confirm the limited assessment scope before continuing.')
      consent.current?.focus()
      return
    }
    const active = new AbortController()
    controller.current = active
    setBusy(true)
    setResult(null)
    const timeout = setTimeout(() => active.abort('timeout'), 65000)
    try {
      const response = await fetch(`${api}/website/analyze`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: url.trim(), acknowledged }), signal: active.signal })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'Assessment unavailable. Please retry.')
      if (active.signal.aborted) return
      setResult(data)
      toast('Website observation ready', 'success')
    } catch (err) {
      if (!active.signal.aborted || active.signal.reason === 'timeout') setError(active.signal.reason === 'timeout' ? 'Assessment timed out. Check the URL and try again.' : err.message === 'Failed to fetch' ? 'Cannot reach the bridge. Check that the backend is running and retry.' : err.message)
    } finally {
      clearTimeout(timeout)
      if (controller.current === active) {
        controller.current = null
        if (!active.signal.aborted || active.signal.reason === 'timeout') setBusy(false)
      }
    }
  }

  async function download() {
    if (downloadController.current || !result) return
    const active = new AbortController()
    downloadController.current = active
    setExporting(true)
    setError('')
    const timeout = setTimeout(() => active.abort('timeout'), 30000)
    try {
      const response = await fetch(`${api}/website/report/pdf`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ report_token: result.report_token }), signal: active.signal })
      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'PDF export failed. Please retry.')
      }
      const blob = await response.blob()
      if (active.signal.aborted) return
      const href = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = href
      link.download = `cortex_website_${result.report.id}.pdf`
      link.click()
      setTimeout(() => URL.revokeObjectURL(href), 1000)
    } catch (err) {
      if (!active.signal.aborted || active.signal.reason === 'timeout') setError(active.signal.reason === 'timeout' ? 'PDF export timed out. Try downloading again.' : err.message)
    } finally {
      clearTimeout(timeout)
      if (downloadController.current === active) {
        downloadController.current = null
        if (!active.signal.aborted || active.signal.reason === 'timeout') setExporting(false)
      }
    }
  }

  return (
    <div className="website-view">
      <h2>Public website observation</h2>
      <p className="field-help">Inspect response headers and transport settings. This is not a device configuration audit, compliance certification, or penetration test.</p>
      <form noValidate onSubmit={analyze} className="card">
        <div className="form-group">
          <label htmlFor="website-url">Website URL</label>
          <input id="website-url" ref={input} type="url" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com/" maxLength={2048} disabled={busy || exporting} autoComplete="off" aria-invalid={fieldError} aria-describedby="website-help website-feedback" />
          <p id="website-help" className="text-dim">Public HTTP/HTTPS only. Do not include credentials or private links. Up to four GET requests including redirects; no page scripts are executed.</p>
        </div>
        <label className="website-consent">
          <input ref={consent} type="checkbox" checked={acknowledged} disabled={busy || exporting} onChange={e => setAcknowledged(e.target.checked)} />
          <span>I may assess this public URL and understand that this is a limited, unauthenticated observation—not a penetration test.</span>
        </label>
        <div className="website-actions">
          <button className="btn btn-primary" type="submit" disabled={busy || exporting} aria-busy={busy}>Analyze website</button>
          {busy && <Spinner />}
        </div>
        <div id="website-feedback" className="website-feedback" role={error ? 'alert' : 'status'}>
          {error || (busy ? 'Observing the response and redirects. This can take up to a minute.' : 'Reports remain in this page only. Download before leaving; export expires after one hour or a backend restart.')}
        </div>
      </form>
      {result && <section aria-label="Website observation results">
        <div className="website-report-head">
          <div><h2>Observation summary</h2><p className="text-dim">{result.report.generated_at} · UTC</p></div>
          <button type="button" className="btn btn-primary" onClick={download} disabled={exporting || busy} aria-busy={exporting}>Download website PDF</button>
        </div>
        <p className="website-evidence">{result.report.final_url}</p>
        <dl className="website-counts">
          {Object.entries(LABELS).map(([key, label]) => <div key={key}><dt>{label}</dt><dd>{result.report.counts[key] || 0}</dd></div>)}
        </dl>
        <p className="text-dim">A passed check applies only to the named observation. Manual review does not mean failed. No overall security score is calculated.</p>
        <section className="card"><h2>Observed route</h2>
          <ol className="website-route">{result.report.hops.map((hop, i) => <li key={i}><strong>HTTP {hop.status}</strong> · {hop.tls ? 'Verified TLS' : 'Unencrypted HTTP'}<p className="website-evidence">{hop.url}</p></li>)}</ol>
        </section>
        <h2>Findings and next steps</h2>
        {result.report.findings.map(f => <article className="website-finding" key={f.id}>
          <header><span className="text-dim">{f.id}</span><h3>{f.title}</h3><span className={`website-verdict website-verdict-${f.verdict}`}>{LABELS[f.verdict]}</span></header>
          <dl>
            <dt>Observed evidence</dt><dd className="website-evidence">{f.evidence}</dd>
            <dt>Interpretation</dt><dd>{f.explanation}</dd>
            <dt>Recommended action</dt><dd>{f.remediation}</dd>
            <dt>How to verify</dt><dd>{f.verification}</dd>
          </dl>
          {f.reference && <a href={f.reference} target="_blank" rel="noreferrer">Technical reference (opens in a new tab)</a>}
        </article>)}
        <section className="card"><h2>Scope and limitations</h2><ul className="website-limits">{result.report.limitations.map(item => <li key={item}>{item}</li>)}</ul></section>
      </section>}
    </div>
  )
}
