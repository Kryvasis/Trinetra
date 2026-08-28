import { useState, useEffect, useCallback } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import Spinner from '../components/Spinner'

export default function SessionDevicesView({ api, toast }) {
  const [searchParams] = useSearchParams()
  const sessionParam = searchParams.get('session') || ''
  const [session, setSession] = useState(sessionParam)
  const [inputSession, setInputSession] = useState(sessionParam)
  const [loading, setLoading] = useState(false)
  const [devices, setDevices] = useState([])
  const [sessionMeta, setSessionMeta] = useState(null)
  const [error, setError] = useState(null)

  const fetchDevices = useCallback(async (sessName) => {
    if (!sessName) return
    setLoading(true)
    setError(null)
    setDevices([])
    setSessionMeta(null)
    try {
      const res = await fetch(`${api}/session/${encodeURIComponent(sessName)}/devices`)
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.error || `HTTP ${res.status}`)
      }
      const data = await res.json()
      setDevices(data.devices || [])
      setSessionMeta(data)
      setSession(sessName)
      if ((data.devices || []).length === 0) {
        toast('No devices found in this session', 'info')
      } else {
        toast(`Loaded ${data.devices.length} device(s)`, 'success')
      }
    } catch (err) {
      setError(err.message)
      toast(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }, [api, toast])

  useEffect(() => {
    if (sessionParam && sessionParam !== session) {
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
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 8 }}>Session Devices</h1>
      <p style={{ color: 'var(--text-dim)', marginBottom: 24, fontSize: 14 }}>
        View all devices within a session, their ingestion method, and per-device compliance results.
      </p>

      <form onSubmit={handleSubmit} style={{ display: 'flex', gap: 8, marginBottom: 24 }}>
        <input
          type="text"
          value={inputSession}
          onChange={e => setInputSession(e.target.value)}
          placeholder="Session name (e.g. multi_vendor_e2e)"
          style={{ flex: 1, maxWidth: 400 }}
        />
        <button type="submit" className="btn-primary" disabled={loading || !inputSession.trim()}>
          {loading ? <><Spinner size={14} /> Loading...</> : 'Load Devices'}
        </button>
      </form>

      {loading && (
        <div className="empty-state card">
          <Spinner size={24} />
          <p style={{ marginTop: 12 }}>Loading device data...</p>
        </div>
      )}

      {error && !loading && (
        <div className="card" style={{ borderLeft: '3px solid var(--red)' }}>
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
          <p>Session "{session}" has no devices. Upload a config first from the <Link to="/">Upload</Link> page.</p>
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

          {/* Device table */}
          <div className="card">
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>Devices in Session "{session}"</h2>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Device ID</th>
                    <th>Vendor</th>
                    <th>Ingestion Method</th>
                    <th>Pass</th>
                    <th>Fail</th>
                    <th>Total</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map(d => {
                    const compliancePct = d.total_checks > 0
                      ? Math.round((d.pass_count / d.total_checks) * 100)
                      : 0
                    return (
                      <tr key={d.device_id}>
                        <td style={{ fontFamily: 'var(--mono)', fontWeight: 600 }}>{d.device_id}</td>
                        <td>
                          <span className="badge badge-info">{d.vendor}</span>
                        </td>
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
                          <div style={{ display: 'flex', gap: 6 }}>
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
        </>
      )}
    </div>
  )
}
