import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import SceneHeader from '../components/SceneHeader'
import Spinner from '../components/Spinner'
import { rememberSession, validSession } from '../utils/activeSession'

const display = value => String(value || '').replaceAll('_', ' ')

export default function AssuranceView({ api, toast }) {
  const [params] = useSearchParams()
  const [session, setSession] = useState(params.get('session') || '')
  const [capabilities, setCapabilities] = useState(null)
  const [capabilityError, setCapabilityError] = useState('')
  const [receipt, setReceipt] = useState(null)
  const [receiptLoading, setReceiptLoading] = useState(false)
  const [receiptError, setReceiptError] = useState('')
  const [candidate, setCandidate] = useState('')
  const [verification, setVerification] = useState(null)
  const [verifyError, setVerifyError] = useState('')
  const [verifying, setVerifying] = useState(false)
  const sessionRef = useRef(null)

  useEffect(() => {
    const controller = new AbortController()
    fetch(`${api}/assurance/capabilities`, { signal: controller.signal })
      .then(async response => {
        const data = await response.json()
        if (!response.ok) throw new Error(data.error || 'Capability data unavailable')
        setCapabilities(data)
      })
      .catch(error => { if (error.name !== 'AbortError') setCapabilityError(error.message) })
    return () => controller.abort()
  }, [api])

  async function generateReceipt(event) {
    event?.preventDefault()
    const name = session.trim()
    if (!validSession(name)) {
      setReceiptError('Use 1–64 letters, numbers, hyphens or underscores.')
      sessionRef.current?.focus()
      return
    }
    setReceiptLoading(true); setReceiptError(''); setReceipt(null)
    try {
      const response = await fetch(`${api}/session/${encodeURIComponent(name)}/integrity-receipt`)
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || 'Receipt generation failed')
      setReceipt(data.receipt); setCandidate(JSON.stringify(data.receipt, null, 2)); rememberSession(name)
      toast('Signed integrity receipt generated', 'success')
    } catch (error) {
      setReceiptError(error.message)
    } finally {
      setReceiptLoading(false)
    }
  }

  function downloadReceipt() {
    if (!receipt) return
    const blob = new Blob([JSON.stringify(receipt, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url; link.download = `cortex-receipt-${receipt.session}.json`; link.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  async function verify(event) {
    event.preventDefault(); setVerification(null); setVerifyError('')
    let parsed
    try { parsed = JSON.parse(candidate) } catch { setVerifyError('Paste a complete Cortex receipt in JSON format.'); return }
    setVerifying(true)
    try {
      const response = await fetch(`${api}/assurance/verify-receipt`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ receipt: parsed }) })
      const data = await response.json()
      setVerification(data)
      if (!response.ok && !data.detail) throw new Error(data.error || 'Receipt verification failed')
    } catch (error) {
      setVerifyError(error.message)
    } finally {
      setVerifying(false)
    }
  }

  return <div>
    <SceneHeader title="Assurance & verification" description="Inspect exactly what Cortex implements, generate signed evidence receipts, and verify integrity without overstating certification or blockchain trust." />

    {capabilityError && <div className="status-panel status-panel-error" role="alert"><h2>Capability registry unavailable</h2><p>{capabilityError}</p></div>}
    {!capabilities && !capabilityError && <div className="assurance-loading" role="status"><Spinner size={20} /> Loading implementation coverage…</div>}
    {capabilities && <>
      <section className="assurance-metrics" aria-labelledby="coverage-heading">
        <div className="section-heading"><div><h2 id="coverage-heading">Implementation coverage</h2><p>Repository-derived counts, generated at {new Date(capabilities.generated_at).toLocaleString()}.</p></div><span className="badge badge-review">Not a certification</span></div>
        <dl><div><dt>Manifest controls</dt><dd>{capabilities.manifest_controls}</dd></div><div><dt>Probe scripts</dt><dd>{capabilities.probe_scripts}</dd></div><div><dt>Automated implementations</dt><dd>{capabilities.automated_probe_implementations}</dd></div><div><dt>Manual-only scripts</dt><dd>{capabilities.manual_review_only}</dd></div></dl>
        <p className="field-help">“Automated implementation” means a script contains an executable verdict path. It does not mean independent production validation.</p>
      </section>

      <section className="card" aria-labelledby="vendor-coverage-heading">
        <div className="section-heading"><div><h2 id="vendor-coverage-heading">Vendor evidence depth</h2><p>Detection and parsing depth are reported separately from production validation.</p></div></div>
        <div className="table-wrap" tabIndex={0} role="region" aria-label="Vendor implementation coverage"><table><caption className="sr-only">Vendor evidence depth and validation status</caption><thead><tr><th scope="col">Vendor</th><th scope="col">Semantic depth</th><th scope="col">Current evidence</th><th scope="col">Production validated</th></tr></thead><tbody>{capabilities.vendors.map(vendor => <tr key={vendor.vendor}><td><strong>{vendor.vendor}</strong></td><td>{display(vendor.semantic_depth)}</td><td>{vendor.validation}</td><td><span className="badge badge-review">{vendor.production_validated ? 'Yes' : 'No'}</span></td></tr>)}</tbody></table></div>
      </section>

      <section className="card" aria-labelledby="control-coverage-heading">
        <div className="section-heading"><div><h2 id="control-coverage-heading">Configuration evaluation matrix</h2><p>{capabilities.configuration_evaluation.notice}</p></div><div className="coverage-key"><span>{capabilities.configuration_evaluation.semantic} semantic</span><span>{capabilities.configuration_evaluation.live_evidence_required} live</span><span>{capabilities.configuration_evaluation.different_assessment_type} other evidence</span></div></div>
        <div className="table-wrap coverage-matrix" tabIndex={0} role="region" aria-label="Configuration evaluation coverage by control"><table><caption className="sr-only">How each manifest control is handled for uploaded configurations</caption><thead><tr><th scope="col">Control</th><th scope="col">Security objective</th><th scope="col">Upload evaluator</th><th scope="col">Possible upload outcome</th><th scope="col">Mapped frameworks</th></tr></thead><tbody>{capabilities.configuration_evaluation.matrix.map(row => <tr key={row.control}><td><strong className="entity-id">{row.control}</strong></td><td>{row.description}</td><td><span className={`badge ${row.mode === 'semantic configuration' ? 'badge-pass' : 'badge-review'}`}>{row.mode}</span></td><td>{row.upload_outcome}</td><td>{row.frameworks.map(display).join(', ')}</td></tr>)}</tbody></table></div>
      </section>

      <section className="assurance-claims" aria-labelledby="claims-heading"><h2 id="claims-heading">Claim boundaries</h2>{Object.entries(capabilities.claims).map(([name, value]) => <div key={name}><strong>{display(name)}</strong><p>{value}</p></div>)}<div><strong>Measured accuracy</strong><p>{capabilities.accuracy.notice}</p></div></section>
    </>}

    <div className="assurance-grid">
      <section className="card" aria-labelledby="receipt-heading"><h2 id="receipt-heading">Generate signed receipt</h2><p>Creates a Merkle root over recorded chain hashes and signs it with the local assessor key.</p><form onSubmit={generateReceipt} className="assurance-form" noValidate><label htmlFor="receipt-session">Assessment session</label><input ref={sessionRef} id="receipt-session" value={session} maxLength={64} onChange={event => setSession(event.target.value)} aria-invalid={!!receiptError} /><button className="btn-primary" disabled={receiptLoading || !session.trim()}>{receiptLoading ? <><Spinner size={14} /> Signing…</> : 'Generate receipt'}</button></form>{receiptError && <p className="field-error" role="alert">{receiptError}</p>}{receipt && <div className="receipt-summary"><span className="badge badge-pass">Ed25519 signed</span><dl><div><dt>Assessment ID</dt><dd><code>{receipt.assessment_id}</code></dd></div><div><dt>Entries</dt><dd>{receipt.entry_count}</dd></div><div><dt>Merkle root</dt><dd><code>{receipt.merkle_root}</code></dd></div></dl><p>{receipt.trust_notice}</p><button type="button" className="btn-secondary" onClick={downloadReceipt}>Download receipt JSON</button></div>}</section>

      <section className="card" aria-labelledby="verify-heading"><h2 id="verify-heading">Verify receipt</h2><p>Checks the Ed25519 signature and, when the session remains available, compares it with current evidence.</p><form onSubmit={verify}><label htmlFor="receipt-json">Receipt JSON</label><textarea id="receipt-json" rows={10} value={candidate} onChange={event => setCandidate(event.target.value)} placeholder="Paste a Cortex integrity receipt" /><button className="btn-primary" disabled={verifying || !candidate.trim()}>{verifying ? <><Spinner size={14} /> Verifying…</> : 'Verify receipt'}</button></form>{verifyError && <p className="field-error" role="alert">{verifyError}</p>}{verification && <div className={`verification-result ${verification.valid ? 'is-valid' : 'is-invalid'}`} role="status"><strong>{verification.valid ? 'Signature valid' : 'Verification failed'}</strong><p>{verification.detail}</p>{verification.valid && <p>{verification.current_evidence_matches === null ? 'The original session is not available for evidence comparison.' : verification.current_evidence_matches ? 'Current session evidence matches this receipt.' : 'Current session evidence no longer matches this receipt.'}</p>}<small>{verification.external_anchor ? 'Independent anchor recorded.' : 'No independent ledger anchor is recorded.'}</small></div>}</section>
    </div>
  </div>
}
