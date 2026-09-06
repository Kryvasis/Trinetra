import { useState, useEffect, useCallback, useRef } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import Spinner from '../components/Spinner'
import SceneHeader from '../components/SceneHeader'
import { rememberSession } from '../utils/activeSession'

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
    if (!sessName) return
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
      setDevices(data.devices || [])
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
        title="Session Devices"
        description="View all devices within a session, their ingestion method, and per-device compliance results."
      />

      <form onSubmit={handleSubmit} noValidate style={{ display: 'flex', gap: 8, marginBottom: 24 }}>
        <input
          type="text"
          value={inputSession}
          onChange={e => setInputSession(e.target.value)}
          placeholder="Session name (e.g. multi_vendor_e2e)"
          aria-label="Session name"
          style={{ flex: 1, maxWidth: 400 }}
        />
        <button type="submit" className="btn-primary" disabled={loading || changingScope || !inputSession.trim()}>
          {loading ? <><Spinner size={14} /> Loading...</> : 'Load Devices'}
        </button>
      </form>

      {removeTarget && <section className="card" aria-labelledby="remove-device-title" style={{ marginBottom: 24 }}>
        <h2 id="remove-device-title">Remove {removeTarget}?</h2>
        <p>This removes the device from session {session}, active counts, and newly generated reports. Historical evidence and earlier exports are retained. You can restore it below.</p>
        <div style={{ display: 'flex', gap: 12, marginTop: 16 }}>
          <button ref={cancelRef} className="btn-secondary" type="button" disabled={changingScope} onClick={() => setRemoveTarget(null)}>Cancel</button>
          <button className="btn-primary" type="button" disabled={changingScope} onClick={() => changeScope(removeTarget)}>{changingScope ? 'Removing…' : 'Remove from assessment'}</button>
        </div>
      </section>}
      {scopeError && <p role="alert">{scopeError}</p>}
      {!!sessionMeta?.removed_devices?.length && <section className="card" style={{ marginBottom: 24 }}>
        <h2>Removed devices</h2>
        <p>Retained evidence is excluded from this assessment. Restore a device to include it again.</p>
        {sessionMeta.removed_devices.map(id => <div key={id} style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'center', marginTop: 12 }}>
          <span>{id}</span><button className="btn-secondary" disabled={changingScope || loading} type="button" onClick={() => changeScope(id, true)} aria-label={`Restore ${id}`}>Restore</button>
        </div>)}
      </section>}

      {loading && (
        <div className="empty-state card">
          <Spinner size={24} />
          <p style={{ marginTop: 12 }}>Loading device data...</p>
        </div>
      )}

      {error && !loading && (
        <div className="card">
          <h3 style={{ color: 'var(--red)', fontSize: 16, marginBottom: 4 }}>Failed to load devices</h3>
          <p style={{ color: 'var(--text-dim)', fontSize: 13 }}>{error}</p>
          <button className="btn-secondary" onClick={() => fetchDevices(inputSession.trim())} style={{ marginTop: 8 }}>
            Retry
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
            <div className="stat-grid" style={{ marginBottom: 24 }}>
              <div className="stat-card">
                <div className="stat-value">{sessionMeta.device_count ?? devices.length}</div>
                <div className="stat-label">Devices</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">
                  {devices.reduce((s, d) => s + d.pass_count, 0)}
                </div>
                <div className="stat-label">Total Pass</div>
              </div>
              <div className="stat-card">
                <div className="stat-value" style={{ color: 'var(--red)' }}>
                  {devices.reduce((s, d) => s + d.fail_count, 0)}
                </div>
                <div className="stat-label">Total Fail</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">
                  {devices.reduce((s, d) => s + d.total_checks, 0)}
                </div>
                <div className="stat-label">Total Checks</div>
              </div>
            </div>
          )}

          {/* Device table — now with distinct PS-required Serial/Hardware/OS columns */}
          <div className="card">
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>Devices in Session "{session}"</h2>
            <div className="table-wrap" style={{ overflowX: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th>Device ID</th>
                    <th>Vendor</th>
                    <th>Serial</th>
                    <th>Hardware</th>
                    <th>OS Version</th>
                    <th>Ingestion Method</th>
                    <th>Pass</th>
                    <th>Fail</th>
                    <th>Total</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map(d => {
                    return (
                      <tr key={d.device_id}>
                        <td style={{ fontFamily: 'var(--mono)', fontWeight: 600 }}>{d.device_id}</td>
                        <td>
                          <span className="badge badge-info">{d.vendor}</span>
                        </td>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{d.serial_number || <span style={{ color: 'var(--text-dim)' }}>—</span>}</td>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{d.hardware_model || <span style={{ color: 'var(--text-dim)' }}>—</span>}</td>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{d.os_version || <span style={{ color: 'var(--text-dim)' }}>{d.vendor === 'Cisco' ? 'auto: IOS' : d.vendor === 'Juniper' ? 'auto: JUNOS' : '—'}</span>}</td>
                        <td>
                          <span className={`badge ${d.ingestion_method === 'config_upload' ? 'badge-pass' : d.ingestion_method === 'live_target' ? 'badge-review' : ''}`}>
                            {d.ingestion_method === 'config_upload' ? 'Config Upload' :
                             d.ingestion_method === 'live_target' ? 'Live Target' :
                             d.ingestion_method}
                          </span>
                          {d.filename && (
                            <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 2 }}>{d.filename}</div>
                          )}
                        </td>
                        <td style={{ fontFamily: 'var(--mono)', color: 'var(--green)' }}>{d.pass_count}</td>
                        <td style={{ fontFamily: 'var(--mono)', color: 'var(--red)' }}>{d.fail_count}</td>
                        <td style={{ fontFamily: 'var(--mono)' }}>{d.total_checks}</td>
                        <td>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                            <button type="button" className="btn-secondary" disabled={changingScope || loading} aria-label={`Remove ${d.device_id}`} onClick={() => { setScopeError(''); setRemoveTarget(d.device_id) }}>Remove</button>
                            <button type="button" className="btn-secondary" disabled={compareLoading || loading} aria-label={`Compare assessments for ${d.device_id}`} onClick={() => fetchComparison(d.device_id)} style={{ fontSize: 12, padding: '4px 10px' }}>Compare</button>
                            <Link
                              to={`/results?session=${encodeURIComponent(session)}`}
                              className="btn-secondary"
                              style={{ fontSize: 12, padding: '4px 10px', textDecoration: 'none' }}
                            >
                              Results
                            </Link>
                            <Link
                              to={`/training?session=${encodeURIComponent(session)}`}
                              className="btn-secondary"
                              style={{ fontSize: 12, padding: '4px 10px', textDecoration: 'none' }}
                            >
                              Training
                            </Link>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {/* Compliance progress per device */}
            <div style={{ marginTop: 20 }}>
              <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 12 }}>Per-Device Compliance</h3>
              {devices.map(d => {
                const pct = d.total_checks > 0 ? Math.round((d.pass_count / d.total_checks) * 100) : 0
                return (
                  <div key={d.device_id} style={{ marginBottom: 12 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span style={{ fontSize: 13, fontFamily: 'var(--mono)' }}>{d.device_id}</span>
                      <span style={{ fontSize: 13, color: 'var(--text-dim)' }}>{pct}% ({d.pass_count}/{d.total_checks})</span>
                    </div>
                    <div className="progress">
                      <div
                        className="progress-bar"
                        style={{
                          width: `${pct}%`,
                          background: pct >= 80 ? 'var(--green)' : pct >= 50 ? 'var(--yellow)' : 'var(--red)',
                        }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Assessment comparison — latest-two per V-code from hash-chained history, no new storage */}
          {(compareLoading || compareError || compareData) && (
            <div className="card" style={{ marginTop: 24 }} aria-live="polite">
              <h2 style={{ fontSize: 16, fontWeight: 600 }}>Assessment comparison{compareDevice ? ` — ${compareDevice}` : ''}</h2>
              {compareLoading && <p><Spinner size={14} /> Comparing latest two assessments…</p>}
              {compareError && !compareLoading && <p role="alert">{compareError}</p>}
              {compareData && !compareLoading && (
                <>
                  <p className="field-help">{compareData.basis}</p>
                  <p style={{ fontSize: 13 }}>
                    Resolved: {compareData.summary?.resolved ?? 0} · Newly failing: {compareData.summary?.['newly failing'] ?? 0} · Unchanged: {compareData.summary?.unchanged ?? 0} · Still unresolved: {compareData.summary?.['still unresolved'] ?? 0}
                  </p>
                  <div className="table-wrap" style={{ overflowX: 'auto' }}>
                    <table>
                      <thead><tr><th>Check</th><th>Before</th><th>After</th><th>Change</th></tr></thead>
                      <tbody>
                        {(compareData.comparisons || []).map(c => (
                          <tr key={c.test_id}>
                            <td style={{ fontFamily: 'var(--mono)' }}>{c.test_id}<br /><small title="assessments compared">{c.assessments_compared}x assessed</small></td>
                            <td><span className="badge badge-review">{c.before.finding_class}</span><br /><small>{c.before.verdict}</small></td>
                            <td><span className="badge badge-review">{c.after.finding_class}</span><br /><small>{c.after.verdict}</small></td>
                            <td><span className={`badge ${c.transition === 'resolved' ? 'badge-pass' : c.transition === 'newly failing' ? 'badge-fail' : 'badge-review'}`}>{c.transition}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}
