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
  const validationHealthy = doctor?.session_validation?.status === 'valid'
  const validationIssues = doctor?.session_validation?.session_errors
    ? Object.values(doctor.session_validation.session_errors).reduce((total, issues) => total + issues.length, 0)
    : 0
  return (
    <div>
      <SceneHeader
        index="05"
        label="Verify"
        title="System status"
        description="Verify local services, evidence integrity, and saved assessment availability."
      />

      <button type="button" className="btn-primary page-primary-action" onClick={loadDoctor} disabled={loading || saving}>
        {loading ? <><Spinner size={14} /> Running diagnostics…</> : 'Run system diagnostics'}
      </button>

      {error && !loading && (
        <div className="status-panel status-panel-error" role="alert">
          <h2>Diagnostics unavailable</h2>
          <p>{error}</p>
          <button type="button" className="btn-secondary" onClick={loadDoctor}>Retry diagnostics</button>
        </div>
      )}

      {doctor && (
        <section className="card system-health" aria-labelledby="system-health-heading">
          <div className="section-heading"><div><h2 id="system-health-heading">System health</h2><p>Current local readiness based on the latest diagnostics run.</p></div><span className="badge badge-info">Local environment</span></div>
          <div className="stat-grid">
            <div className="stat-card">
              <div className="stat-value">{doctor.test_definitions?.count ?? '—'}</div>
              <div className="stat-label">Test definitions</div>
            </div>
            <div className="stat-card">
              <div className={`stat-value stat-value-status ${validationHealthy ? 'status-good' : 'status-warning'}`}>
                {validationHealthy ? 'Healthy' : 'Needs attention'}
              </div>
              <div className="stat-label">Session validation{validationIssues ? ` · ${validationIssues} ${validationIssues === 1 ? 'issue' : 'issues'}` : ''}</div>
            </div>
            <div className="stat-card">
              <div className="stat-value stat-value-status status-neutral">
                Not tested
              </div>
              <div className="stat-label">AI connectivity</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{sessions.length + archived.length}</div>
              <div className="stat-label">Saved sessions · including removed</div>
            </div>
          </div>

          {/* Session errors */}
          {doctor.session_validation?.session_errors && Object.keys(doctor.session_validation.session_errors).length > 0 && (
            <section className="diagnostic-section" aria-labelledby="validation-issues-heading">
              <h3 id="validation-issues-heading">Session validation issues</h3>
              <div className="table-wrap" tabIndex={0} role="region" aria-label="Session validation issues">
                <table>
                  <caption className="sr-only">Validation issues found in saved sessions</caption>
                  <thead>
                    <tr>
                      <th scope="col">Session</th>
                      <th scope="col">Issues</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(doctor.session_validation.session_errors).map(([sess, errs]) => (
                      <tr key={sess}>
                        <td><code>{sess}</code></td>
                        <td>{errs.length > 0 ? <ul className="diagnostic-errors">{errs.map((issue, index) => <li key={index}>{issue}</li>)}</ul> : <span className="status-good">No issues</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </section>
      )}

      {/* Session list with device links */}
      {doctor && (
        <section className="card" aria-labelledby="saved-sessions-heading">
          <div className="section-heading"><div><h2 ref={listRef} id="saved-sessions-heading" tabIndex={-1}>Saved sessions</h2><p>Open an assessment workflow or remove it from this list. Stored evidence remains recoverable.</p></div><span className="badge badge-info">{sessions.length} active</span></div>
          <div className="assessment-toolbar"><label htmlFor="session-search">Find session</label><input ref={searchRef} id="session-search" type="search" value={query} onChange={event => { setQuery(event.target.value); setPage(0) }} />{query && <button type="button" className="btn-secondary" aria-label="Clear session search" onClick={() => { setQuery(''); setPage(0); searchRef.current?.focus() }}>Clear</button>}</div>
          {query && filtered.length === 0 && <p>No sessions match this search.</p>}
          {actionError && <p className="inline-error" role="alert">{actionError}</p>}
          {removeTarget && <section className="inline-confirmation" aria-labelledby="remove-session-title" onKeyDown={event => { if (event.key === 'Escape' && !saving) { setRemoveTarget(''); triggerRef.current?.focus() } }}>
            <h3 id="remove-session-title">Remove {removeTarget} from the list?</h3>
            <p>Devices, findings and reports will not be deleted. You can restore this session from Removed sessions. Saved links still work.</p>
            <div className="action-cluster">
              <button ref={cancelRef} type="button" className="btn-secondary" disabled={saving} onClick={() => { setRemoveTarget(''); triggerRef.current?.focus() }}>Cancel</button>
              <button type="button" className="btn-danger" disabled={saving} onClick={() => changeArchive(removeTarget, true)}>{saving ? 'Removing…' : 'Remove session'}</button>
            </div>
          </section>}
          {sessions.length === 0 && <p>No sessions in the main list. Upload a new assessment or restore one below.</p>}
          {filtered.length > 0 && <div className="table-wrap" tabIndex={0} role="region" aria-label="Saved sessions">
            <table>
              <caption className="sr-only">Saved Cortex assessment sessions</caption>
              <thead>
                <tr>
                  <th scope="col">Session</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(currentPage * 10, (currentPage + 1) * 10).map(s => (
                  <tr key={s}>
                    <td><code>{s}</code></td>
                    <td>
                      <div className="action-cluster action-cluster-compact">
                        <Link
                          to={`/results?session=${encodeURIComponent(s)}`}
                          className="btn-secondary"
                        >
                          Results
                        </Link>
                        <Link
                          to={`/devices?session=${encodeURIComponent(s)}`}
                          className="btn-secondary"
                        >
                          Devices
                        </Link>
                        <Link
                          to={`/training?session=${encodeURIComponent(s)}`}
                          className="btn-secondary"
                        >
                          Training
                        </Link>
                        <button type="button" className="btn-danger" disabled={loading || saving} aria-label={`Remove session ${s}`} onClick={event => { triggerRef.current = event.currentTarget; setRemoveTarget(s); setActionError('') }}>Remove</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>}
          {filtered.length > 0 && <div className="assessment-pagination"><span role="status">{currentPage * 10 + 1}–{Math.min((currentPage + 1) * 10, filtered.length)} of {filtered.length} sessions</span><button type="button" className="btn-secondary" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</button><button type="button" className="btn-secondary" disabled={(currentPage + 1) * 10 >= filtered.length} onClick={() => setPage(currentPage + 1)}>Next</button></div>}
          {archived.length > 0 && <details className="retained-items">
            <summary>Removed sessions ({archived.length})</summary>
            <p>These assessments are retained on disk. Restore returns them to the main list.</p>
            <ul className="retained-list">
              {archived.map(name => <li key={name}>
                <code>{name}</code>
                <button type="button" className="btn-secondary" disabled={loading || saving} aria-label={`Restore session ${name}`} onClick={() => changeArchive(name, false)}>Restore</button>
              </li>)}
            </ul>
          </details>}
        </section>
      )}

      {!doctor && !loading && !error && (
        <div className="empty-state card">
          <h3>System status</h3>
          <p>Run system diagnostics to check service health and configuration readiness.</p>
        </div>
      )}
    </div>
  )
}
