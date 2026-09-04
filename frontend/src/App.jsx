import { useState, useCallback, useEffect } from 'react'
import { BrowserRouter, Routes, Route, NavLink, Navigate, useLocation, useNavigate } from 'react-router-dom'
import UploadView from './pages/UploadView'
import ResultsView from './pages/ResultsView'
import TrainingView from './pages/TrainingView'
import DashboardView from './pages/DashboardView'
import SessionDevicesView from './pages/SessionDevicesView'
import Toast from './components/Toast'
import ThreatField from './components/ThreatField'
import OverviewView from './pages/OverviewView'
import ActiveSession from './components/ActiveSession'
import { sessionSearch } from './utils/activeSession'

const API = '/api'

const NAV_ITEMS = [
  { to: '/dashboard', label: 'Overview' },
  { to: '/upload', label: 'Upload & collect' },
  { to: '/results', label: 'Results' },
  { to: '/training', label: 'Training' },
  { to: '/devices', label: 'Devices' },
  { to: '/system', label: 'System' },
]

const TITLES = {
  '/upload': 'Upload & collect',
  '/website': 'Website Analysis',
  '/results': 'Results & evidence',
  '/training': 'Training Loop',
  '/devices': 'Session Devices',
  '/dashboard': 'Overview',
  '/system': 'System Status',
}

function IntroExperience({ entering, onOpen }) {
  useEffect(() => {
    document.title = 'Cortex — Network Configuration Intelligence'
  }, [])

  return (
    <section className={`intro-experience${entering ? ' is-entering' : ''}`} aria-label="Cortex introduction">
      <ThreatField />
      <header className="intro-masthead">
        <div className="intro-brand" aria-label="Cortex">
          <span className="brand-glyph" aria-hidden="true"><i /><i /></span>
          <span className="brand-copy"><strong>CORTEX</strong><small>Configuration intelligence</small></span>
        </div>
        <span className="intro-edition">SIH / Cybersecurity + Blockchain</span>
      </header>

      <div className="intro-copy">
        <span className="intro-kicker">Continuous configuration assurance</span>
        <h1>See the risks<br />hidden in your network.</h1>
        <p>
          Cortex turns raw device configurations into clear compliance evidence,
          remediation guidance, and an auditable security record.
        </p>
      </div>

      <button className="intro-action" type="button" onClick={onOpen} disabled={entering}>
        <span>{entering ? <>Opening<br />workspace</> : <>Open<br />workspace</>}</span>
      </button>

      <div className="intro-foot" aria-hidden="true">
        <span>01 — Observe</span><span>02 — Evaluate</span><span>03 — Verify</span>
      </div>
      <div className="intro-wipe" aria-hidden="true" />
    </section>
  )
}

function WorkspaceShell({ addToast, sessionBanner }) {
  const location = useLocation()
  const sessionQuery = sessionSearch('', new URLSearchParams(location.search).get('session'))

  useEffect(() => {
    document.title = `${TITLES[location.pathname] || 'Compliance Scanner'} — Cortex`
    window.scrollTo({ top: 0, left: 0, behavior: 'auto' })
    document.getElementById('main-content')?.focus({ preventScroll: true })
  }, [location.pathname])

  return (
    <div className="app-shell workspace-shell">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <nav className="nav" aria-label="Primary navigation">
        <div className="nav-inner">
          <NavLink to={`/dashboard${sessionQuery}`} className="nav-brand" aria-label="Cortex overview">
            <span className="brand-glyph" aria-hidden="true"><i /><i /></span>
            <span className="brand-copy"><strong>CORTEX</strong><small>Configuration intelligence</small></span>
          </NavLink>
          <div className="nav-links">
            {NAV_ITEMS.map(item => (
              <NavLink key={item.to} to={`${item.to}${sessionQuery}`} end={item.end}>
                {item.label}
              </NavLink>
            ))}
          </div>
        </div>
      </nav>
      {sessionBanner}
      <main className="container app-main" id="main-content" tabIndex={-1}>
        <div key={location.pathname} className="route-stage">
          <Routes>
            <Route path="/" element={<Navigate to={location.search ? `/upload${location.search}` : '/dashboard'} replace />} />
            <Route path="/upload" element={<UploadView api={API} toast={addToast} />} />
            <Route path="/website" element={<Navigate to="/upload?source=website" replace />} />
            <Route path="/results" element={<ResultsView api={API} toast={addToast} />} />
            <Route path="/training" element={<TrainingView api={API} toast={addToast} />} />
            <Route path="/devices" element={<SessionDevicesView api={API} toast={addToast} />} />
            <Route path="/dashboard" element={<OverviewView api={API} />} />
            <Route path="/system" element={<DashboardView api={API} toast={addToast} />} />
            <Route path="*" element={<div className="empty-state card"><h1>Page not found</h1><p>Choose a workspace page from the navigation.</p><NavLink to="/dashboard">Return to overview</NavLink></div>} />
          </Routes>
        </div>
      </main>
    </div>
  )
}

function Experience({ addToast }) {
  const location = useLocation()
  const navigate = useNavigate()
  const [workspaceOpen, setWorkspaceOpen] = useState(location.pathname !== '/' || new URLSearchParams(location.search).has('source'))
  const [entering, setEntering] = useState(false)

  useEffect(() => {
    if (location.pathname !== '/') setWorkspaceOpen(true)
  }, [location.pathname])

  useEffect(() => {
    if (!entering) return undefined
    const timer = window.setTimeout(() => {
      setWorkspaceOpen(true)
      setEntering(false)
      navigate('/dashboard')
    }, 760)
    return () => window.clearTimeout(timer)
  }, [entering, navigate])

  const openWorkspace = () => {
    if (entering) return
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (reducedMotion) {
      setWorkspaceOpen(true)
      navigate('/dashboard')
      return
    }
    setEntering(true)
  }

  if (!workspaceOpen) return <IntroExperience entering={entering} onOpen={openWorkspace} />
  return <ActiveSession><WorkspaceShell addToast={addToast} /></ActiveSession>
}

export default function App() {
  const [toasts, setToasts] = useState([])

  const addToast = useCallback((msg, type = 'info') => {
    const id = Date.now()
    setToasts(prev => [...prev, { id, msg, type }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000)
  }, [])

  return (
    <BrowserRouter>
      <Experience addToast={addToast} />
      <Toast toasts={toasts} />
    </BrowserRouter>
  )
}
