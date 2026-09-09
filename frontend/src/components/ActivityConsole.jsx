import { useCallback, useEffect, useRef, useState } from 'react'
import { ACTIVITY_EVENT } from '../utils/activityStream'

const TERMINAL_LIMIT = 80

function timestamp(value) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '--:--:--' : date.toLocaleTimeString([], { hour12: false })
}

function traceText(trace, session) {
  const header = [
    '# Cortex runtime evidence trace',
    `# session: ${session || 'not-selected'}`,
    `# operation: ${trace.operation_id || 'not-started'}`,
    `# status: ${trace.status || 'idle'}`,
  ].join('\n')
  const body = (trace.events || []).map(event => (
    `[${timestamp(event.timestamp)}] ${String(event.stage || 'activity').toUpperCase()}\n` +
    `$ ${event.command}\n${event.message}`
  )).join('\n\n')
  return `${header}\n\n${body}`
}

export default function ActivityConsole({ api, session, toast }) {
  const [watchedSession, setWatchedSession] = useState(session)
  const [trace, setTrace] = useState({ status: 'idle', events: [] })
  const [open, setOpen] = useState(false)
  const [paused, setPaused] = useState(false)
  const [error, setError] = useState('')
  const [copying, setCopying] = useState(false)
  const bodyRef = useRef(null)
  const launcherRef = useRef(null)
  const closeRef = useRef(null)
  const requestRef = useRef(null)
  const eventCountRef = useRef(0)
  const statusRef = useRef('idle')

  const load = useCallback(async () => {
    if (!watchedSession || paused || document.hidden) return
    requestRef.current?.abort()
    const controller = new AbortController()
    requestRef.current = controller
    try {
      const response = await fetch(`${api}/session/${encodeURIComponent(watchedSession)}/activity`, {
        signal: controller.signal,
        cache: 'no-store',
      })
      if (response.status === 404) {
        statusRef.current = 'idle'
        setTrace({ status: 'idle', events: [] })
        setError('')
        return
      }
      if (!response.ok) throw new Error(`Activity service returned HTTP ${response.status}`)
      const result = await response.json()
      statusRef.current = result.status || 'idle'
      setTrace({ ...result, events: Array.isArray(result.events) ? result.events.slice(-TERMINAL_LIMIT) : [] })
      setError('')
    } catch (err) {
      if (err.name !== 'AbortError') setError('Live activity is temporarily unavailable. Assessment actions continue normally.')
    } finally {
      if (requestRef.current === controller) requestRef.current = null
    }
  }, [api, paused, watchedSession])

  useEffect(() => {
    setWatchedSession(session)
  }, [session])

  useEffect(() => {
    statusRef.current = 'idle'
    setTrace({ status: 'idle', events: [] })
    setError('')
    eventCountRef.current = 0
  }, [watchedSession])

  useEffect(() => {
    if (!watchedSession || paused) return undefined
    let disposed = false
    let timer
    const poll = async () => {
      await load()
      if (!disposed) timer = window.setTimeout(poll, statusRef.current === 'running' ? 700 : 2400)
    }
    poll()
    return () => {
      disposed = true
      window.clearTimeout(timer)
      requestRef.current?.abort()
    }
  }, [load, paused, watchedSession])

  useEffect(() => {
    function refresh(event) {
      if (event.detail?.session) setWatchedSession(event.detail.session)
      if (!event.detail?.session || event.detail.session === watchedSession) load()
    }
    window.addEventListener(ACTIVITY_EVENT, refresh)
    return () => window.removeEventListener(ACTIVITY_EVENT, refresh)
  }, [load, watchedSession])

  useEffect(() => {
    const count = trace.events.length
    if (open && !paused && count > eventCountRef.current) {
      bodyRef.current?.scrollTo({ top: bodyRef.current.scrollHeight, behavior: 'smooth' })
    }
    eventCountRef.current = count
  }, [open, paused, trace.events])

  useEffect(() => {
    if (!open) return undefined
    const focusTimer = window.requestAnimationFrame(() => closeRef.current?.focus())
    function closeOnEscape(event) {
      if (event.key !== 'Escape') return
      setOpen(false)
      window.requestAnimationFrame(() => launcherRef.current?.focus())
    }
    window.addEventListener('keydown', closeOnEscape)
    return () => {
      window.cancelAnimationFrame(focusTimer)
      window.removeEventListener('keydown', closeOnEscape)
    }
  }, [open])

  function closeDrawer() {
    setOpen(false)
    window.requestAnimationFrame(() => launcherRef.current?.focus())
  }

  async function copyTrace() {
    if (!trace.events.length || copying) return
    setCopying(true)
    try {
      await navigator.clipboard.writeText(traceText(trace, watchedSession))
      toast('Sanitized activity trace copied', 'success')
    } catch {
      toast('The activity trace could not be copied. Check browser clipboard permission.', 'error')
    } finally {
      setCopying(false)
    }
  }

  const events = trace.events || []
  const running = trace.status === 'running'
  const stateLabel = error ? 'Unavailable' : paused ? 'Paused' : running ? 'Live' : trace.status === 'idle' ? 'Standing by' : trace.status
  const stateClass = error ? 'unavailable' : trace.status
  const activityPath = watchedSession ? `/api/session/${encodeURIComponent(watchedSession)}/activity` : '/api/session/[not-selected]/activity'
  const stages = [...new Set(events.map(event => event.stage).filter(Boolean))]
  const refreshMode = paused ? 'manual' : running ? '700ms follow' : '2.4s snapshot'
  const lastUpdated = trace.updated_at ? timestamp(trace.updated_at) : '--:--:--'

  return <>
    <button
      ref={launcherRef}
      className="runtime-console-launcher"
      type="button"
      onClick={() => setOpen(true)}
      aria-expanded={open}
      aria-controls="runtime-console-drawer"
      hidden={open}
    >
      <svg viewBox="0 0 20 20" aria-hidden="true">
        <path d="m4.5 6 3.25 4-3.25 4M10 14h5.5" />
      </svg>
      <span className="runtime-launcher-copy"><strong>Runtime</strong><small>{stateLabel} · {events.length} {events.length === 1 ? 'event' : 'events'}</small></span>
    </button>

    {open && <aside className="runtime-console" id="runtime-console-drawer" aria-labelledby="runtime-console-title">
      <header className="runtime-console-header">
        <div className="runtime-console-identity">
          <span className="runtime-console-mark" aria-hidden="true"><i /><i /></span>
          <div>
            <div className="runtime-console-title"><h2 id="runtime-console-title">Cortex runtime</h2><span>evidence shell</span></div>
            <p>{watchedSession ? `localhost / sessions / ${watchedSession}` : 'localhost / no session selected'}</p>
          </div>
        </div>
        <div className="runtime-console-actions">
          <span className={`runtime-console-state state-${stateClass}`} role="status">{stateLabel}</span>
          <button type="button" onClick={() => setPaused(value => !value)} aria-pressed={paused} disabled={!watchedSession}>{paused ? 'Resume' : 'Pause'}</button>
          <button type="button" onClick={copyTrace} disabled={!events.length || copying}>{copying ? 'Copying' : 'Copy trace'}</button>
          <button ref={closeRef} type="button" onClick={closeDrawer}>Close</button>
        </div>
      </header>

        <div className="runtime-commandbar" aria-label="Live trace request">
          <div className="runtime-commandbar-prompt">
            <span className="runtime-user">cortex@bridge</span><span className="runtime-path">:~/assessment</span><span aria-hidden="true">$</span>
            <code>fetch GET {activityPath} --cache no-store</code>
          </div>
          <div className="runtime-operation"><span>operation</span><code>{trace.operation_id || 'awaiting-request'}</code></div>
        </div>
        <div className="runtime-tracebar" aria-label="Trace metadata">
          <span><b>transport</b> local HTTP</span>
          <span><b>mode</b> {refreshMode}</span>
          <span><b>updated</b> {lastUpdated}</span>
          <span className="runtime-stage-path"><b>path</b> {stages.length ? stages.join(' / ') : 'waiting for intake'}</span>
        </div>
        <div ref={bodyRef} className="runtime-console-body" id="runtime-console-body" role="log" aria-live="polite" aria-relevant="additions text">
          {events.length ? events.map((event, index) => <article className={`runtime-line level-${event.level}`} key={`${trace.operation_id}-${event.id}`}>
            <div className="runtime-line-meta">
              <span className="runtime-sequence">job.{String(event.id).padStart(3, '0')}</span>
              <time dateTime={event.timestamp}>{timestamp(event.timestamp)}</time>
              <strong>{event.stage}</strong>
              <span className="runtime-branch" aria-hidden="true">{index === events.length - 1 ? '└─' : '├─'}</span>
            </div>
            <div className="runtime-line-payload">
              <div className="runtime-line-command"><span className="runtime-host" aria-hidden="true">cortex@bridge</span><span aria-hidden="true">$</span><code>{event.command}</code></div>
              <p><span aria-hidden="true">stdout ›</span>{event.message}</p>
            </div>
          </article>) : <div className="runtime-console-empty">
            <div className="runtime-empty-banner" aria-hidden="true"><b>CORTEX RUNTIME TRACE</b><span>sanitized operational channel</span></div>
            <code><span className="runtime-user">cortex@bridge</span><span aria-hidden="true">:~/assessment$</span> fetch GET {activityPath} --cache no-store</code>
            <p>{watchedSession ? 'No backend-confirmed activity is recorded. Start an upload, paste, or authorized network collection.' : 'Select or create a session. The shell renders only confirmed backend stages and sanitized command forms.'}</p>
          </div>}
          {error && <p className="runtime-console-error" role="alert">{error}</p>}
        </div>
        <footer className="runtime-console-footer">
          <span><b>buffer</b> {String(events.length).padStart(3, '0')} / 120</span>
          <span><b>channel</b> {paused ? 'held' : 'open'}</span>
          <span><b>redaction</b> enforced</span>
          <span className="runtime-footer-note">Raw configurations, credentials and temporary paths excluded</span>
        </footer>
    </aside>}
  </>
}
