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
  const terminalPath = watchedSession ? `~/sessions/${watchedSession}` : '~/assessment'

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
        <h2 id="runtime-console-title">cortex@bridge: {terminalPath}</h2>
        <div className="runtime-console-actions">
          <span className={`runtime-console-state state-${stateClass}`} role="status">{stateLabel}</span>
          <button type="button" onClick={() => setPaused(value => !value)} aria-pressed={paused} disabled={!watchedSession}>{paused ? 'Resume' : 'Pause'}</button>
          <button type="button" onClick={copyTrace} disabled={!events.length || copying}>{copying ? 'Copying' : 'Copy trace'}</button>
          <button ref={closeRef} type="button" onClick={closeDrawer}>Close</button>
        </div>
      </header>

      <div ref={bodyRef} className="runtime-console-body" id="runtime-console-body" role="log" aria-live="polite" aria-relevant="additions text">
          {events.length ? events.map(event => <article className={`runtime-line level-${event.level}`} key={`${trace.operation_id}-${event.id}`}>
            <div className="runtime-line-command">
              <time dateTime={event.timestamp}>[{timestamp(event.timestamp)}]</time>
              <span className="runtime-user" aria-hidden="true">cortex@bridge</span><span className="runtime-path" aria-hidden="true">:{terminalPath}$</span>
              <code>{event.command}</code>
            </div>
            <p>{event.message}</p>
          </article>) : <div className="runtime-console-empty">
            <div className="runtime-line-command">
              <span className="runtime-user" aria-hidden="true">cortex@bridge</span><span className="runtime-path" aria-hidden="true">:{terminalPath}$</span>
              <code>await activity</code>
            </div>
            <p>{watchedSession ? 'Waiting for assessment activity.' : 'Select or create a session to begin.'}</p>
          </div>}
          {error && <p className="runtime-console-error" role="alert">{error}</p>}
      </div>
    </aside>}
  </>
}
