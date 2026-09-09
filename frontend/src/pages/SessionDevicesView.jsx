import { useState, useEffect, useCallback, useRef } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import Spinner from '../components/Spinner'
import SceneHeader from '../components/SceneHeader'
import { rememberSession, validSession } from '../utils/activeSession'
import { count, summarizeDevices } from '../utils/assessmentSummary'

export default function SessionDevicesView({ api, toast }) {
  const [searchParams] = useSearchParams()
  const sessionParam = searchParams.get('session') || ''
  const [session, setSession] = useState(sessionParam)
  const [inputSession, setInputSession] = useState(sessionParam)
  const [loading, setLoading] = useState(false)
  const [devices, setDevices] = useState([])
  const [sessionMeta, setSessionMeta] = useState(null)
  const [error, setError] = useState(null)
  const requestRef = useRef(null)
  const [removeTarget, setRemoveTarget] = useState(null)
  const [changingScope, setChangingScope] = useState(false)
  const [scopeError, setScopeError] = useState('')
  const [compareDevice, setCompareDevice] = useState(null)
  const [compareData, setCompareData] = useState(null)
  const [compareLoading, setCompareLoading] = useState(false)
  const [compareError, setCompareError] = useState('')
  const cancelRef = useRef(null)
  const scopeRequestRef = useRef(null)
  const triggerRef = useRef(null)
  const headingRef = useRef(null)
  const inputRef = useRef(null)
  const searchRef = useRef(null)
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(0)
  const filtered = devices.filter(device => [device.device_id, device.vendor, device.hardware_model, device.os_version].some(value => String(value || '').toLowerCase().includes(query.trim().toLowerCase())))
  const currentPage = Math.min(page, Math.max(0, Math.ceil(filtered.length / 10) - 1))
  const visible = filtered.slice(currentPage * 10, (currentPage + 1) * 10)
  const totals = summarizeDevices(devices)
  function cancelRemoval() { setRemoveTarget(null); triggerRef.current?.focus() }
  useEffect(() => () => { scopeRequestRef.current?.abort(); scopeRequestRef.current = null }, [])
  useEffect(() => { if (removeTarget) cancelRef.current?.focus() }, [removeTarget])

  async function fetchComparison(deviceId) {
    if (!session || compareLoading) return
    setCompareDevice(deviceId); setCompareData(null); setCompareError('')
    setCompareLoading(true)
    try {
      const res = await fetch(`${api}/session/${encodeURIComponent(session)}/compare?device_id=${encodeURIComponent(deviceId)}`)
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`)
      setCompareData(data)
    } catch (err) {
      setCompareError(err.message)
    } finally {
      setCompareLoading(false)
    }
  }

  async function changeScope(deviceId, restore = false) {
    if (changingScope) return
    setChangingScope(true)
    setScopeError('')
    const controller = new AbortController()
    scopeRequestRef.current = controller
    const timeout = setTimeout(() => controller.abort(), 30000)
    try {
      const response = await fetch(`${api}/session/${encodeURIComponent(session)}/devices/${encodeURIComponent(deviceId)}${restore ? '/restore' : ''}`, {
        method: restore ? 'POST' : 'DELETE', signal: controller.signal,
      })
      if (!response.ok) throw new Error((await response.json()).error || 'Could not update device scope')
      if (scopeRequestRef.current !== controller) return
      setRemoveTarget(null)
      toast(restore ? 'Device restored to assessment' : 'Device removed; historical evidence retained', 'success')
      await fetchDevices(session)
      ;(headingRef.current || document.getElementById('main-content'))?.focus()
    } catch (err) {
      if (scopeRequestRef.current !== controller) return
      setScopeError(err.name === 'AbortError' ? 'Request timed out. Reload Devices to check whether the change completed before retrying.' : err.message)
    } finally {
      clearTimeout(timeout)
      if (scopeRequestRef.current === controller) { scopeRequestRef.current = null; setChangingScope(false) }
    }
  }

  useEffect(() => () => { requestRef.current?.abort(); requestRef.current = null }, [])

  const fetchDevices = useCallback(async (sessName) => {
    if (!validSession(sessName)) { setError('Use 1–64 letters, numbers, hyphens or underscores.'); inputRef.current?.focus(); return }
    setRemoveTarget(null)
    requestRef.current?.abort()
    const controller = new AbortController()
    requestRef.current = controller
    const timeout = setTimeout(() => controller.abort(), 30000)
    setLoading(true)
    setError(null)
    setDevices([])
    setSessionMeta(null)
    try {
      const res = await fetch(`${api}/session/${encodeURIComponent(sessName)}/devices`, { signal: controller.signal })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.error || `HTTP ${res.status}`)
      }
      const data = await res.json()
      if (requestRef.current !== controller) return
      if (!Array.isArray(data.devices)) throw new Error('The device response is incomplete. Retry or check System diagnostics.')
      setDevices(data.devices)
      setSessionMeta(data)
      setSession(sessName)
      rememberSession(sessName)
      if ((data.devices || []).length === 0) {
        toast('No devices found in this session', 'info')
      } else {
        toast(`Loaded ${data.devices.length} device(s)`, 'success')
      }
    } catch (err) {
      if (requestRef.current !== controller) return
      const message = err.name === 'AbortError' ? 'The request timed out. Check the backend and retry.' : err.message
      setError(message)
      toast(message, 'error')
    } finally {
      clearTimeout(timeout)
      if (requestRef.current === controller) { requestRef.current = null; setLoading(false) }
    }
  }, [api, toast])

  useEffect(() => {
    scopeRequestRef.current?.abort(); scopeRequestRef.current = null
    setChangingScope(false); setScopeError(''); setQuery(''); setPage(0)
    if (sessionParam) {
      setInputSession(sessionParam)
      fetchDevices(sessionParam)
    }
  }, [sessionParam, fetchDevices])

  const handleSubmit = (e) => {
    e.preventDefault()
    const s = inputSession.trim()
    if (!s) return
    fetchDevices(s)
  }

  return (
    <div>
      <SceneHeader
        index="04"
        label="Observe"
        title="Session devices"
        description="Review device inventory, evidence sources, recorded outcomes, and assessment-to-assessment changes."
      />

      <form onSubmit={handleSubmit} noValidate className="assessment-toolbar" aria-busy={loading}>
        <label htmlFor="devices-session">Saved session</label>
        <input
          ref={inputRef} id="devices-session" maxLength={64} disabled={loading || changingScope}
          type="text"
          value={inputSession}
          onChange={e => setInputSession(e.target.value)}
          placeholder="Session name (e.g. multi_vendor_e2e)"
          aria-invalid={!!error && !validSession(inputSession.trim())}
          aria-describedby={error ? 'devices-error' : undefined}
        />
        <button type="submit" className="btn-primary" disabled={loading || changingScope || !inputSession.trim()}>
          {loading ? <><Spinner size={14} /> Loading…</> : 'Load devices'}
        </button>
      </form>

      {removeTarget && <section className="inline-confirmation" aria-labelledby="remove-device-title" onKeyDown={event => { if (event.key === 'Escape' && !changingScope) cancelRemoval() }}>
        <h2 id="remove-device-title">Remove {removeTarget}?</h2>
        <p>This removes the device from session {session}, active counts, and newly generated reports. Historical evidence and earlier exports are retained. You can restore it below.</p>
        <div className="action-cluster">
          <button ref={cancelRef} className="btn-secondary" type="button" disabled={changingScope} onClick={cancelRemoval}>Cancel</button>
          <button className="btn-danger" type="button" disabled={changingScope} onClick={() => changeScope(removeTarget)}>{changingScope ? 'Removing…' : 'Remove from assessment'}</button>
        </div>
      </section>}
      {scopeError && <p className="inline-error" role="alert">{scopeError}</p>}
      {!!sessionMeta?.removed_devices?.length && <section className="card retained-items">
        <div className="section-heading section-heading-compact"><h2>Removed devices</h2><span className="badge badge-info">{sessionMeta.removed_devices.length} retained</span></div>
        <p>Retained evidence is excluded from this assessment. Restore a device to include it again.</p>
        <ul className="retained-list">{sessionMeta.removed_devices.map(id => <li key={id}>
          <code>{id}</code><button className="btn-secondary" disabled={changingScope || loading} type="button" onClick={() => changeScope(id, true)} aria-label={`Restore ${id}`}>Restore</button>
        </li>)}</ul>
      </section>}

      {loading && (
        <div className="empty-state card">
          <Spinner size={24} />
          <p>Loading device data…</p>
        </div>
      )}

      {error && !loading && (
        <div className="status-panel status-panel-error" role="alert" id="devices-error">
          <h2>Device inventory unavailable</h2>
          <p>{error}</p>
          <button type="button" className="btn-secondary" onClick={() => fetchDevices(inputSession.trim())}>
            Retry request
          </button>
        </div>
      )}

      {!loading && !error && devices.length === 0 && session && (
        <div className="empty-state card">
          <h3>No devices found</h3>
          <p>Session "{session}" has no devices. Upload a config first from the <Link to="/upload">Upload & collect</Link> page.</p>
        </div>
      )}

      {!loading && !error && devices.length === 0 && !session && (
        <div className="empty-state card">
          <h3>Enter a session name</h3>
          <p>Type a session name above to view its devices and per-device compliance results.</p>
        </div>
      )}

      {devices.length > 0 && (
        <>
          {/* Session summary */}
          {sessionMeta && (
            <div className="stat-grid session-stat-grid">
              <div className="stat-card">
                <div className="stat-value">{sessionMeta.device_count ?? devices.length}</div>
                <div className="stat-label">Devices</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">
                  {totals.passed}
                </div>
                <div className="stat-label">Passed checks</div>
              </div>
              <div className="stat-card">
                <div className="stat-value status-risk">
                  {totals.failed}
                </div>
                <div className="stat-label">Failed checks</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">
                  {totals.total}
                </div>
                <div className="stat-label">Recorded checks</div>
              </div>
            </div>
          )}

          {/* Device table — now with distinct PS-required Serial/Hardware/OS columns */}
          <section className="card" aria-labelledby="session-device-heading">
            <div className="section-heading"><div><h2 ref={headingRef} id="session-device-heading" tabIndex={-1}>Devices in session “{session}”</h2><p>Inventory and evidence retained for the selected assessment.</p></div><span className="badge badge-info">{devices.length} in scope</span></div>
            <div className="assessment-toolbar">
              <label htmlFor="device-search">Find device</label>
              <input ref={searchRef} id="device-search" type="search" value={query} onChange={event => { setQuery(event.target.value); setPage(0) }} placeholder="Device, vendor, hardware or OS" />
              {query && <button type="button" className="btn-secondary" onClick={() => { setQuery(''); setPage(0); searchRef.current?.focus() }}>Clear search</button>}
            </div>
            <p className="field-help" id="device-table-help">Scroll the table horizontally to see hardware details and device actions. Counts include retained check history.</p>
            <div className="table-wrap" tabIndex={0} role="region" aria-label="Session devices" aria-describedby="device-table-help">
              <table className="device-table">
                <caption className="sr-only">Devices in the selected assessment</caption>
                <thead>
                  <tr>
                    <th scope="col">Device ID</th>
                    <th scope="col">Vendor</th>
                    <th scope="col">Serial</th>
                    <th scope="col">Hardware</th>
                    <th scope="col">OS version</th>
                    <th scope="col">Evidence source</th>
                    <th scope="col">Pass</th>
                    <th scope="col">Fail</th>
                    <th scope="col">Total</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map(d => {
                    return (
                      <tr key={d.device_id}>
                        <td><code className="entity-id">{d.device_id}</code></td>
                        <td>
                          <span className="badge badge-info">{d.vendor}</span>
                        </td>
                        <td><code className="table-detail">{d.serial_number || '—'}</code></td>
                        <td><code className="table-detail">{d.hardware_model || '—'}</code></td>
                        <td><code className="table-detail">{d.os_version || 'Not recorded'}</code></td>
                        <td>
                          <span className={`badge ${d.ingestion_method === 'config_upload' ? 'badge-pass' : d.ingestion_method === 'live_target' ? 'badge-review' : ''}`}>
                            {d.ingestion_method === 'config_upload' ? 'Config Upload' :
                             d.ingestion_method === 'live_target' ? 'Live Target' :
                             d.ingestion_method}
                          </span>
                          {d.filename && (
                            <div className="table-detail">{d.filename}</div>
                          )}
                        </td>
                        <td><code className="status-good">{d.pass_count}</code></td>
                        <td><code className="status-risk">{d.fail_count}</code></td>
                        <td><code>{d.total_checks}</code></td>
                        <td>
                          <div className="action-cluster action-cluster-compact">
                            <button type="button" className="btn-danger" disabled={changingScope || loading} aria-label={`Remove ${d.device_id}`} onClick={event => { triggerRef.current = event.currentTarget; setScopeError(''); setRemoveTarget(d.device_id) }}>Remove</button>
                            <button type="button" className="btn-secondary" disabled={compareLoading || loading} aria-label={`Compare assessments for ${d.device_id}`} onClick={() => fetchComparison(d.device_id)}>Compare</button>
                            <Link
                              to={`/results?session=${encodeURIComponent(session)}`}
                              className="btn-secondary"
                            >
                              Results
                            </Link>
                            <Link
                              to={`/training?session=${encodeURIComponent(session)}`}
                              className="btn-secondary"
                            >
                              Training
                            </Link>
                            <a
                              href={`${api}/session/${encodeURIComponent(session)}/devices/${encodeURIComponent(d.device_id)}/pdf`}
                              className="btn-secondary"
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              Device PDF
                            </a>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
            {!filtered.length && <p role="status">No devices match “{query}”. Clear the search to see all devices.</p>}
            <div className="assessment-pagination" aria-label="Device pages"><span role="status">{filtered.length ? currentPage * 10 + 1 : 0}–{Math.min((currentPage + 1) * 10, filtered.length)} of {filtered.length} devices</span><button type="button" className="btn-secondary" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</button><button type="button" className="btn-secondary" disabled={(currentPage + 1) * 10 >= filtered.length} onClick={() => setPage(currentPage + 1)}>Next</button></div>

            {/* Compliance progress per device */}
            <section className="device-rates" aria-labelledby="device-rates-heading">
              <h3 id="device-rates-heading">Recorded-check pass rate · displayed devices</h3>
              <p className="field-help">Unresolved checks need review. These rates do not establish compliance.</p>
              {visible.map(d => {
                const pct = count(d.total_checks) > 0 ? Math.min(100, Math.round((count(d.pass_count) / count(d.total_checks)) * 100)) : 0
                return (
                  <div className="device-rate" key={d.device_id}>
                    <div>
                      <code>{d.device_id}</code>
                      <span>{count(d.total_checks) ? `${pct}%` : '—'} ({count(d.pass_count)}/{count(d.total_checks)})</span>
                    </div>
                    <div className="progress">
                      <div
                        className="progress-bar"
                        style={{
                          width: `${pct}%`,
                          background: 'var(--text)',
                        }}
                      />
                    </div>
                  </div>
                )
              })}
            </section>
          </section>

          {/* Assessment comparison — two complete hash-chained upload snapshots. */}
          {(compareLoading || compareError || compareData) && (
            <section className="card comparison-panel" aria-live="polite" aria-labelledby="comparison-heading">
              <h2 id="comparison-heading">Assessment comparison{compareDevice ? ` — ${compareDevice}` : ''}</h2>
              {compareLoading && <p><Spinner size={14} /> Comparing the latest complete snapshots…</p>}
              {compareError && !compareLoading && <p role="alert">{compareError}</p>}
              {compareData && !compareLoading && (
                <>
                  <p className="field-help">{compareData.basis}</p>
                  {compareData.before_assessment_id && <p className="comparison-identities"><span>Before <code>{compareData.before_assessment_id}</code></span><span>After <code>{compareData.after_assessment_id}</code></span></p>}
                  <dl className="comparison-summary"><div><dt>Resolved</dt><dd>{compareData.summary?.resolved ?? 0}</dd></div><div><dt>Newly failing</dt><dd>{compareData.summary?.['newly failing'] ?? 0}</dd></div><div><dt>Unchanged</dt><dd>{compareData.summary?.unchanged ?? 0}</dd></div><div><dt>Still unresolved</dt><dd>{compareData.summary?.['still unresolved'] ?? 0}</dd></div><div><dt>Not comparable</dt><dd>{compareData.summary?.['not comparable'] ?? 0}</dd></div></dl>
                  <div className="table-wrap" tabIndex={0} role="region" aria-label="Latest assessment comparison">
                    <table>
                      <caption className="sr-only">Two complete recorded assessment snapshots for this device</caption>
                      <thead><tr><th scope="col">Check</th><th scope="col">Before</th><th scope="col">After</th><th scope="col">Change</th></tr></thead>
                      <tbody>
                        {(compareData.comparisons || []).map(c => (
                          <tr key={c.test_id}>
                            <td><code>{c.test_id}</code></td>
                            <td>{c.before ? <><span className="badge badge-review">{c.before.finding_class}</span><br /><small>{c.before.verdict}</small></> : <span className="badge badge-review">Not present</span>}</td>
                            <td>{c.after ? <><span className="badge badge-review">{c.after.finding_class}</span><br /><small>{c.after.verdict}</small></> : <span className="badge badge-review">Not present</span>}</td>
                            <td><span className={`badge ${c.transition === 'resolved' ? 'badge-pass' : c.transition === 'newly failing' ? 'badge-fail' : 'badge-review'}`}>{c.transition}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </section>
          )}
        </>
      )}
    </div>
  )
}
