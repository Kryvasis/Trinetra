import { useState, useRef, useEffect } from 'react'
import { Link } from 'react-router-dom'
import Spinner from '../components/Spinner'
import SceneHeader from '../components/SceneHeader'

export default function DashboardView({ api, toast }) {
  const [loading, setLoading] = useState(false)
  const [doctor, setDoctor] = useState(null)
  const [sessions, setSessions] = useState([])
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(0)
  const searchRef = useRef(null)
  const [archived, setArchived] = useState([])
  const [removeTarget, setRemoveTarget] = useState('')
  const [saving, setSaving] = useState(false)
  const [actionError, setActionError] = useState('')
  const cancelRef = useRef(null)
  const triggerRef = useRef(null)
  const listRef = useRef(null)
  const mutationRef = useRef(null)
  const [error, setError] = useState(null)
  const abortRef = useRef(null)
  const initialLoadRef = useRef(null)

  useEffect(() => () => {
    abortRef.current?.abort()
    abortRef.current = null
    mutationRef.current?.abort()
    mutationRef.current = null
  }, [])
  useEffect(() => { if (removeTarget) cancelRef.current?.focus() }, [removeTarget])

  const changeArchive = async (name, remove) => {
    if (mutationRef.current) return
    const controller = new AbortController()
    mutationRef.current = controller
    setSaving(true)
    setActionError('')
    const timeout = setTimeout(() => controller.abort(), 30000)
    try {
      const response = await fetch(`${api}/session/${encodeURIComponent(name)}/archive`, {
        method: remove ? 'POST' : 'DELETE', signal: controller.signal,
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`)
      if (mutationRef.current !== controller) return
      setSessions(items => remove ? items.filter(item => item !== name) : [...new Set([...items, name])].sort())
      setArchived(items => remove ? [...new Set([...items, name])].sort() : items.filter(item => item !== name))
      setRemoveTarget('')
      if (remove) window.dispatchEvent(new CustomEvent('cortex:session-removed', { detail: name }))
      toast(remove ? 'Session removed from list. Evidence retained.' : 'Session restored.', 'success')
      listRef.current?.focus()
    } catch (err) {
      if (mutationRef.current !== controller) return
      setActionError(err.name === 'AbortError'
        ? 'Request timed out; it may have completed. Run diagnostics to refresh the list before retrying.'
        : `${err.message}. Refresh diagnostics and retry.`)
    } finally {
      clearTimeout(timeout)
      if (mutationRef.current === controller) {
        mutationRef.current = null
        setSaving(false)
      }
    }
  }

  const loadDoctor = async (silent = false) => {
    if (abortRef.current || mutationRef.current) return
    setRemoveTarget('')
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
      if (abortRef.current !== controller) return
      setDoctor(data)
      setSessions(Array.isArray(data.sessions) ? data.sessions : [])
      setArchived(Array.isArray(data.archived_sessions) ? data.archived_sessions : [])
      setActionError('')
      if (silent !== true) toast('Health check loaded', 'success')
    } catch (err) {
      if (abortRef.current !== controller) return
      if (err.name === 'AbortError') {
        toast('Doctor timed out. Is the bridge running?', 'error')
        setError('Bridge unreachable — timed out after 30s')
      } else {
        toast(err.message, 'error')
        setError(err.message)
      }
    } finally {
      clearTimeout(timeoutId)
      if (abortRef.current === controller) {
        abortRef.current = null
        setLoading(false)
      }
    }
  }

  useEffect(() => { initialLoadRef.current = loadDoctor })
  useEffect(() => { initialLoadRef.current(true) }, [])
  const filtered = sessions.filter(name => name.toLowerCase().includes(query.toLowerCase()))
  const currentPage = Math.min(page, Math.max(0, Math.ceil(filtered.length / 10) - 1))
  return (
    <div>
      <SceneHeader
        index="05"
        label="Verify"
        title="System Status"
        description="System health diagnostics and session overview."
      />

      <button className="btn-primary" onClick={loadDoctor} disabled={loading || saving} style={{ marginBottom: 24 }}>
        {loading ? <><Spinner size={14} /> Running diagnostics...</> : 'Run system diagnostics'}
      </button>

      {error && !loading && (
        <div className="card" style={{ marginBottom: 24 }}>
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
                Not tested
              </div>
              <div className="stat-label">AI connectivity</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{sessions.length + archived.length}</div>
              <div className="stat-label">Saved sessions, including removed</div>
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
      {doctor && (
        <div className="card">
          <h2 ref={listRef} tabIndex={-1} style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>Saved sessions</h2>
          <p>Remove hides a session from this list. Its evidence stays saved and can be restored below.</p>
          <div className="assessment-toolbar"><label htmlFor="session-search">Find session</label><input ref={searchRef} id="session-search" type="search" value={query} onChange={event => { setQuery(event.target.value); setPage(0) }} />{query && <button className="btn-secondary" aria-label="Clear session search" onClick={() => { setQuery(''); setPage(0); searchRef.current?.focus() }}>Clear</button>}</div>
          {query && filtered.length === 0 && <p>No sessions match this search.</p>}
          {actionError && <p role="alert" style={{ color: 'var(--red)' }}>{actionError}</p>}
          {removeTarget && <section aria-labelledby="remove-session-title" style={{ margin: '20px 0', padding: 16, border: '1px solid var(--border-strong)', borderRadius: 12 }}>
            <h3 id="remove-session-title">Remove {removeTarget} from the list?</h3>
            <p>Devices, findings and reports will not be deleted. You can restore this session from Removed sessions. Saved links still work.</p>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <button ref={cancelRef} className="btn-secondary" disabled={saving} onClick={() => { setRemoveTarget(''); triggerRef.current?.focus() }}>Cancel</button>
              <button className="btn-primary" disabled={saving} onClick={() => changeArchive(removeTarget, true)}>{saving ? 'Removing…' : 'Remove session'}</button>
            </div>
          </section>}
          {sessions.length === 0 && <p>No sessions in the main list. Upload a new assessment or restore one below.</p>}
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Session</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(currentPage * 10, (currentPage + 1) * 10).map(s => (
                  <tr key={s}>
                    <td style={{ fontFamily: 'var(--mono)' }}>{s}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
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
                        <button className="btn-secondary" disabled={loading || saving} aria-label={`Remove session ${s}`} onClick={event => { triggerRef.current = event.currentTarget; setRemoveTarget(s); setActionError('') }}>Remove</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {filtered.length > 0 && <div className="assessment-pagination"><span role="status">{currentPage * 10 + 1}–{Math.min((currentPage + 1) * 10, filtered.length)} of {filtered.length} sessions</span><button className="btn-secondary" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</button><button className="btn-secondary" disabled={(currentPage + 1) * 10 >= filtered.length} onClick={() => setPage(currentPage + 1)}>Next</button></div>}
          {archived.length > 0 && <details style={{ marginTop: 24 }}>
            <summary>Removed sessions ({archived.length})</summary>
            <p>These assessments are retained on disk. Restore returns them to the main list.</p>
            <ul style={{ listStyle: 'none', padding: 0 }}>
              {archived.map(name => <li key={name} style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'center', marginTop: 12 }}>
                <span style={{ overflowWrap: 'anywhere', flex: 1 }}>{name}</span>
                <button className="btn-secondary" disabled={loading || saving} aria-label={`Restore session ${name}`} onClick={() => changeArchive(name, false)}>Restore</button>
              </li>)}
            </ul>
          </details>}
        </div>
      )}

      {!doctor && !loading && !error && (
        <div className="empty-state card">
          <h3>System Status</h3>
          <p>Run system diagnostics to check service health and configuration readiness.</p>
        </div>
      )}
    </div>
  )
}
