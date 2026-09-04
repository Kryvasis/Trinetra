import { useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import SceneHeader from '../components/SceneHeader'
import WorkspaceIcon from '../components/WorkspaceIcon'
import Spinner from '../components/Spinner'
import { count, summarizeDevices } from '../utils/assessmentSummary'

export default function OverviewView({ api }) {
  const [params, setParams] = useSearchParams()
  const requestedSession = params.get('session') || ''
  const [input, setInput] = useState(requestedSession)
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [revision, setRevision] = useState(0)
  const inputRef = useRef(null)

  useEffect(() => {
    setInput(requestedSession)
    setData(null)
    setError('')
    setLoading(false)
    if (!requestedSession) return undefined
    const controller = new AbortController()
    let active = true
    setLoading(true)
    const timeout = setTimeout(() => controller.abort(), 30000)
    async function load() {
      try {
        const response = await fetch(`${api}/session/${encodeURIComponent(requestedSession)}/devices`, { signal: controller.signal })
        if (!response.ok) throw new Error(response.status === 404 ? 'Session not found. Check its name, or collect evidence to create one.' : 'The session could not be loaded. Check the local backend and try again.')
        const result = await response.json()
        if (!Array.isArray(result.devices)) throw new Error('The session response is incomplete. Try again or check System diagnostics.')
        if (active) setData(result)
      } catch (err) {
        if (active) setError(err.name === 'AbortError' ? 'The request timed out. Check the local backend, then retry.' : err.message)
      } finally {
        clearTimeout(timeout)
        if (active) setLoading(false)
      }
    }
    load()
    return () => { active = false; controller.abort(); clearTimeout(timeout) }
  }, [api, requestedSession, revision])

  const totals = summarizeDevices(data?.devices || [])
  const sessionQuery = data ? `?session=${encodeURIComponent(requestedSession)}` : ''
  const values = [totals.passed, totals.failed, totals.unresolved]
  const labels = ['Passed', 'Failed', 'Unresolved']
  let offset = 0

  function openSession(event) {
    event.preventDefault()
    if (loading) return
    const name = input.trim()
    if (!name) { inputRef.current?.focus(); return }
    if (name === requestedSession) setRevision(value => value + 1)
    else setParams({ session: name })
  }

  return <div className="overview">
    <div className="overview-heading">
      <SceneHeader title="Assessment overview" description="From configuration evidence to a clear review decision." />
      <Link to="/upload" className="btn-primary"><WorkspaceIcon name="upload" />Collect evidence</Link>
    </div>

    <form className="session-toolbar" onSubmit={openSession} noValidate aria-busy={loading}>
      <label htmlFor="overview-session">Session</label>
      <input ref={inputRef} id="overview-session" value={input} onChange={event => setInput(event.target.value)} placeholder="Enter an existing session name" autoComplete="off" spellCheck="false" />
      <button className="btn-secondary" disabled={loading || !input.trim()}>{loading ? <Spinner size={16} /> : <WorkspaceIcon name="refresh" />} {loading ? 'Loading session' : 'Open session'}</button>
      <span className="session-context" role="status">{data ? `${data.devices.length} ${data.devices.length === 1 ? 'device' : 'devices'} loaded` : 'Configuration assessments'}</span>
    </form>
    {error && <div className="overview-error" role="alert"><p>{error}</p><button className="btn-secondary" onClick={() => setRevision(value => value + 1)} disabled={loading}>Retry</button></div>}

    <div className="overview-metrics" aria-busy={loading}>
      <div className="metric-stack">
        <section className="overview-panel compact-metric"><h2>Devices in scope</h2><strong>{data ? data.devices.length : '—'}</strong><span>{data ? 'In the selected session' : 'Open a session to view devices'}</span><WorkspaceIcon name="device" size={32} /></section>
        <section className="overview-panel compact-metric"><h2>Checks recorded</h2><strong>{data ? totals.total : '—'}</strong><span>Configuration evidence only</span><WorkspaceIcon name="check" size={32} /></section>
      </div>
      <section className="overview-panel outcome-panel">
        <h2>Check outcomes</h2>
        <div className="outcome-visual">
          <svg viewBox="0 0 180 180" aria-hidden="true"><circle cx="90" cy="90" r="70" fill="none" stroke="var(--surface3)" strokeWidth="19" />{totals.total > 0 && values.map((value, index) => {
            const length = value / totals.total * 100
            const segment = <circle key={labels[index]} className={`outcome-segment segment-${index}`} cx="90" cy="90" r="70" fill="none" strokeWidth="19" pathLength="100" strokeDasharray={`${length} ${100 - length}`} strokeDashoffset={-offset} transform="rotate(-90 90 90)" />
            offset += length
            return segment
          })}</svg>
          <div><strong>{data ? totals.total : '—'}</strong><span>{data ? 'Total checks' : 'No session loaded'}</span></div>
        </div>
        <dl className="outcome-legend">{labels.map((label, index) => <div key={label}><dt><i className={`legend-swatch segment-${index}`} />{label}</dt><dd>{data ? values[index] : '—'}</dd></div>)}</dl>
      </section>
      <section className="overview-panel review-panel">
        <h2>Review readiness</h2>
        <WorkspaceIcon name="shield" size={42} />
        <h3>{!data ? 'Start with the evidence.' : !totals.total ? 'No checks recorded yet.' : totals.failed + totals.unresolved > 0 ? 'Review required.' : 'Check results available.'}</h3>
        <p>{!data ? 'Load a session to distinguish confirmed findings from checks that still need a decision.' : `${totals.failed} failed and ${totals.unresolved} unresolved checks. Review the underlying evidence before drawing conclusions.`}</p>
        <Link to={data ? `/results${sessionQuery}` : '/upload'}>{data ? 'Review assessment' : 'Create an assessment'}<WorkspaceIcon name="arrow" /></Link>
        <small>Check outcomes are not a compliance certification.</small>
      </section>
    </div>

    <section className="overview-panel assessment-flow" aria-labelledby="flow-title">
      <div className="panel-heading"><h2 id="flow-title">Assessment workflow</h2><span>Evidence → evaluation → review</span></div>
      <ol className="flow-stages">
        <li><span className="flow-stage-label">Collection</span><Link to="/upload"><WorkspaceIcon name="upload" /><strong>Configuration evidence</strong><small>Upload, paste or collect</small><WorkspaceIcon name="arrow" /></Link><Link className="flow-secondary" to="/upload?source=website">Website observations<WorkspaceIcon name="arrow" /></Link></li>
        <li><span className="flow-stage-label">Inventory</span><Link to={`/devices${sessionQuery}`}><WorkspaceIcon name="device" /><strong>Device scope</strong><small>Vendor and source details</small><WorkspaceIcon name="arrow" /></Link></li>
        <li><span className="flow-stage-label">Evaluation</span><Link to={`/results${sessionQuery}`}><WorkspaceIcon name="check" /><strong>Mapped checks</strong><small>Pass, fail and unresolved</small><WorkspaceIcon name="arrow" /></Link></li>
        <li><span className="flow-stage-label">Review</span><Link to={`/training${sessionQuery}`}><WorkspaceIcon name="report" /><strong>Evidence review</strong><small>Inspect unrecognized lines</small><WorkspaceIcon name="arrow" /></Link></li>
      </ol>
      <p className="flow-note">Website observations use a separate report and do not contribute to configuration check totals.</p>
    </section>

    <section className="overview-panel device-preview" aria-labelledby="preview-title">
      <div className="panel-heading"><h2 id="preview-title">Session devices</h2><Link to={`/devices${sessionQuery}`}>View devices <WorkspaceIcon name="arrow" /></Link></div>
      {data?.devices.length ? <><div className="table-wrap"><table><caption className="sr-only">First five devices in the selected session</caption><thead><tr><th scope="col">Device</th><th scope="col">Vendor</th><th scope="col">Source</th><th scope="col">Passed</th><th scope="col">Failed</th><th scope="col">Unresolved</th></tr></thead><tbody>{data.devices.slice(0, 5).map(device => <tr key={device.device_id}><td><Link to={`/devices${sessionQuery}`}>{device.device_id}</Link></td><td>{device.vendor}</td><td>{device.ingestion_method}</td><td>{count(device.pass_count)}</td><td>{count(device.fail_count)}</td><td>{Math.max(0, count(device.total_checks) - count(device.pass_count) - count(device.fail_count))}</td></tr>)}</tbody></table></div><p className="flow-note">Showing {Math.min(5, data.devices.length)} of {data.devices.length} devices.</p></> : <div className="preview-empty"><WorkspaceIcon name="device" size={26} /><div><h3>{data ? 'No devices in this session' : 'Your evidence starts here'}</h3><p>{data ? 'Collect a configuration to add devices and assessment checks.' : 'Open a session above, or collect your first configuration.'}</p></div><Link className="btn-secondary" to="/upload">Collect evidence<WorkspaceIcon name="arrow" /></Link></div>}
    </section>
  </div>
}
