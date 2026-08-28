import { useState, useRef } from 'react'
import { Link } from 'react-router-dom'
import Spinner from '../components/Spinner'

export default function DashboardView({ api, toast }) {
  const [loading, setLoading] = useState(false)
  const [doctor, setDoctor] = useState(null)
  const [sessions, setSessions] = useState([])
  const [error, setError] = useState(null)
  const abortRef = useRef(null)

  const loadDoctor = async () => {
    setLoading(true)
    setError(null)
    const controller = new AbortController()
    abortRef.current = controller
    const timeoutId = setTimeout(() => controller.abort(), 30000)

    try {
      const res = await fetch(`${api}/doctor`, { signal: controller.signal })
      clearTimeout(timeoutId)
      if (!res.ok) throw new Error(`Doctor failed: ${res.status}`)
      const data = await res.json()
      setDoctor(data)
      const errs = data.session_validation?.session_errors || {}
      const sessionNames = Object.keys(errs)
      if (sessionNames.length > 0) {
        setSessions(sessionNames)
      }
      toast('Health check loaded', 'success')
    } catch (err) {
      if (err.name === 'AbortError') {
        toast('Doctor timed out. Is the bridge running?', 'error')
        setError('Bridge unreachable — timed out after 30s')
      } else {
        toast(err.message, 'error')
        setError(err.message)
      }
    } finally {
      clearTimeout(timeoutId)
      abortRef.current = null
      setLoading(false)
    }
  }

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 8 }}>System Status</h1>
      <p style={{ color: 'var(--text-dim)', marginBottom: 24, fontSize: 14 }}>
        System health diagnostics and session overview.
      </p>

      <button className="btn-primary" onClick={loadDoctor} disabled={loading} style={{ marginBottom: 24 }}>
        {loading ? <><Spinner size={14} /> Running Doctor...</> : 'Run trinetra -doctor'}
      </button>

      {error && !loading && (
        <div className="card" style={{ borderLeft: '3px solid var(--red)', marginBottom: 24 }}>
          <h3 style={{ color: 'var(--red)', fontSize: 16, marginBottom: 4 }}>Diagnostics failed</h3>
          <p style={{ color: 'var(--text-dim)', fontSize: 13 }}>{error}</p>
          <button className="btn-secondary" onClick={loadDoctor} style={{ marginTop: 8 }}>Retry</button>
        </div>
      )}

      {doctor && (
        <div className="card" style={{ marginBottom: 24 }}>
          <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>System Health</h2>
          <div className="stat-grid">
            <div className="stat-card">
              <div className="stat-value">{doctor.test_definitions?.count ?? '—'}</div>
              <div className="stat-label">Test Definitions</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{
                color: doctor.session_validation?.status === 'valid' ? 'var(--green)' : 'var(--yellow)'
              }}>
                {doctor.session_validation?.status ?? 'unknown'}
              </div>
              <div className="stat-label">Sessions Status</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{
                color: doctor.ai_integration?.available ? 'var(--green)' : 'var(--yellow)'
              }}>
                {doctor.ai_integration?.available ? 'Connected' : 'Unconfigured'}
              </div>
              <div className="stat-label">AI Integration</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{doctor.ai_integration?.brain_state_sessions ?? 0}</div>
              <div className="stat-label">Brain Sessions</div>
            </div>
          </div>

          {/* Session errors */}
          {doctor.session_validation?.session_errors && Object.keys(doctor.session_validation.session_errors).length > 0 && (
            <div style={{ marginTop: 16 }}>
              <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Session Validation Issues</h3>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Session</th>
                      <th>Errors</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(doctor.session_validation.session_errors).map(([sess, errs]) => (
                      <tr key={sess}>
                        <td style={{ fontFamily: 'var(--mono)' }}>{sess}</td>
                        <td>{errs.length > 0 ? errs.map((e, i) => (
                          <div key={i} style={{ fontSize: 12, color: 'var(--red)' }}>{e}</div>
                        )) : (
                          <span style={{ color: 'var(--green)' }}>OK</span>
                        )}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Session list with device links */}
      {sessions.length > 0 && (
        <div className="card">
          <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>Sessions</h2>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Session</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map(s => (
                  <tr key={s}>
                    <td style={{ fontFamily: 'var(--mono)' }}>{s}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <Link
                          to={`/results?session=${encodeURIComponent(s)}`}
                          className="btn-secondary"
                          style={{ fontSize: 12, padding: '4px 10px', textDecoration: 'none' }}
                        >
                          Results
                        </Link>
                        <Link
                          to={`/devices?session=${encodeURIComponent(s)}`}
                          className="btn-secondary"
                          style={{ fontSize: 12, padding: '4px 10px', textDecoration: 'none' }}
                        >
                          Devices
                        </Link>
                        <Link
                          to={`/training?session=${encodeURIComponent(s)}`}
                          className="btn-secondary"
                          style={{ fontSize: 12, padding: '4px 10px', textDecoration: 'none' }}
                        >
                          Training
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {!doctor && !loading && !error && (
        <div className="empty-state card">
          <h3>System Status</h3>
          <p>Click "Run trinetra -doctor" to check system health.</p>
        </div>
      )}
    </div>
  )
}
