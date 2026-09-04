import { cloneElement, useEffect, useRef, useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { IDLE_TIMEOUT, SESSION_EVENT, readSession, validSession, writeSession, sessionSearch } from '../utils/activeSession'

export default function ActiveSession({ children }) {
  const location = useLocation()
  const navigate = useNavigate()
  const [initial] = useState(readSession)
  const [active, setActive] = useState(initial && !initial.expired ? initial.name : '')
  const [expiredName, setExpiredName] = useState(initial?.expired ? initial.name : '')
  const [notice, setNotice] = useState(initial?.expired ? 'Session selection expired. Saved assessments have not been deleted.' : '')
  const [generation, setGeneration] = useState(0)
  const [resetDestination, setResetDestination] = useState('')
  const lastActivity = useRef(initial?.lastActivity || Date.now())
  const requested = new URLSearchParams(location.search).get('session')
  const selected = requested === expiredName ? '' : validSession(requested) ? requested : active
  const search = sessionSearch(location.search, selected)

  useEffect(() => {
    if (resetDestination === location.pathname && !location.search) setResetDestination('')
  }, [resetDestination, location.pathname, location.search])

  useEffect(() => {
    if (selected && selected !== active) {
      setActive(selected)
      lastActivity.current = Date.now()
      writeSession(selected)
      setNotice('')
    }
  }, [selected, active])

  useEffect(() => {
    function choose(event) {
      const name = event.detail
      if (!validSession(name)) return
      setExpiredName('')
      setNotice('')
      lastActivity.current = Date.now()
      navigate({ pathname: location.pathname, search: sessionSearch(location.search, name) }, { replace: true })
    }
    window.addEventListener(SESSION_EVENT, choose)
    return () => window.removeEventListener(SESSION_EVENT, choose)
  }, [location.pathname, location.search, navigate])

  useEffect(() => {
    function removed(event) {
      if (!active || event.detail !== active) return
      writeSession(active, Date.now() - IDLE_TIMEOUT)
      setExpiredName(active)
      setActive('')
      setNotice('Session removed from the list. Its saved evidence can be restored in System.')
      navigate('/system', { replace: true })
    }
    window.addEventListener('cortex:session-removed', removed)
    return () => window.removeEventListener('cortex:session-removed', removed)
  }, [active, navigate])

  useEffect(() => {
    if (!active) return undefined
    function expire() {
      // Retain an expired timestamp so refreshing an old URL cannot silently revive it.
      writeSession(active, Date.now() - IDLE_TIMEOUT)
      setExpiredName(active)
      setActive('')
      setNotice('Session selection expired after 30 minutes without activity. Saved assessments are still available.')
      setGeneration(value => value + 1)
      setResetDestination('/dashboard')
    }
    function check() {
      if (Date.now() - lastActivity.current >= IDLE_TIMEOUT) { expire(); return false }
      return true
    }
    function touch() {
      if (!check() || document.hidden) return
      lastActivity.current = Date.now()
      writeSession(active, lastActivity.current)
    }
    const timer = window.setInterval(check, 1000)
    const events = ['pointerdown', 'keydown', 'wheel', 'touchstart']
    events.forEach(event => window.addEventListener(event, touch, { passive: true }))
    window.addEventListener('focus', check)
    document.addEventListener('visibilitychange', check)
    return () => {
      window.clearInterval(timer)
      events.forEach(event => window.removeEventListener(event, touch))
      window.removeEventListener('focus', check)
      document.removeEventListener('visibilitychange', check)
    }
  }, [active, navigate])

  if (resetDestination && (location.pathname !== resetDestination || location.search)) return <Navigate to={resetDestination} replace />
  if (search !== location.search) return <Navigate to={{ pathname: location.pathname, search, hash: location.hash }} replace />

  function reset() {
    if (active) writeSession(active, Date.now() - IDLE_TIMEOUT)
    setExpiredName(active)
    setActive('')
    setNotice('Session selection cleared. Your saved assessments have not been deleted.')
    setGeneration(value => value + 1)
    setResetDestination('/upload')
  }

  const banner = <>
    <div className="container" style={{ paddingTop: 12, display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 12 }}>
      <span role="status" style={{ overflowWrap: 'anywhere' }}>{active ? `Active session: ${active}` : notice}</span>
      {active && <><small>Clears after 30 minutes of inactivity</small><button type="button" className="btn-secondary" onClick={reset}>New assessment</button></>}
    </div>
  </>
  return <div key={generation}>{cloneElement(children, { sessionBanner: banner })}</div>
}
