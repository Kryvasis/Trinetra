import { useState, useCallback } from 'react'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import UploadView from './pages/UploadView'
import ResultsView from './pages/ResultsView'
import TrainingView from './pages/TrainingView'
import DashboardView from './pages/DashboardView'
import SessionDevicesView from './pages/SessionDevicesView'
import Toast from './components/Toast'

const API = '/api'

export default function App() {
  const [toasts, setToasts] = useState([])

  const addToast = useCallback((msg, type = 'info') => {
    const id = Date.now()
    setToasts(prev => [...prev, { id, msg, type }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000)
  }, [])

  return (
    <BrowserRouter>
      <nav className="nav">
        <div className="container">
          <div className="nav-brand"><span>Trinetra</span> Compliance Scanner</div>
          <div className="nav-links">
            <NavLink to="/" end>Upload</NavLink>
            <NavLink to="/results">Results</NavLink>
            <NavLink to="/training">Training</NavLink>
            <NavLink to="/devices">Devices</NavLink>
            <NavLink to="/dashboard">System</NavLink>
          </div>
        </div>
      </nav>
      <div className="container" style={{ paddingTop: 32, paddingBottom: 48 }}>
        <Routes>
          <Route path="/" element={<UploadView api={API} toast={addToast} />} />
          <Route path="/results" element={<ResultsView api={API} toast={addToast} />} />
          <Route path="/training" element={<TrainingView api={API} toast={addToast} />} />
          <Route path="/devices" element={<SessionDevicesView api={API} toast={addToast} />} />
          <Route path="/dashboard" element={<DashboardView api={API} toast={addToast} />} />
        </Routes>
      </div>
      <Toast toasts={toasts} />
    </BrowserRouter>
  )
}
