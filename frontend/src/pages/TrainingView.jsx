import { useState, useEffect } from 'react'
import Spinner from '../components/Spinner'

export default function TrainingView({ api, toast }) {
  const params = new URLSearchParams(window.location.search)
  const [session, setSession] = useState(params.get('session') || '')
  const [inputSession, setInputSession] = useState(params.get('session') || '')
  const [loading, setLoading] = useState(false)
  const [unrecognized, setUnrecognized] = useState([])
  const [totalBefore, setTotalBefore] = useState(0)
  const [totalAfter, setTotalAfter] = useState(0)

  // Training form state
  const [selectedLine, setSelectedLine] = useState(null)
  const [vendor, setVendor] = useState('Cisco')
  const [pattern, setPattern] = useState('')
  const [category, setCategory] = useState('')
  const [controlMapping, setControlMapping] = useState('')
  const [remediation, setRemediation] = useState('')
  const [training, setTraining] = useState(false)

  useEffect(() => {
    const s = params.get('session')
    if (s && s !== session) {
      setSession(s)
      setInputSession(s)
    }
  }, [params.get('session')])

  const fetchUnrecognized = async (sessName) => {
    setLoading(true)
    try {
      const res = await fetch(`${api}/session/${sessName}/unrecognized`)
      if (!res.ok) throw new Error(`Failed to load: ${res.status}`)
      const data = await res.json()
      const lines = []
      Object.entries(data.unrecognized_by_device || {}).forEach(([dev, devLines]) => {
        devLines.forEach(line => lines.push({ device: dev, line }))
      })
      setUnrecognized(lines)
      setTotalBefore(lines.length)
      if (lines.length === 0) {
        toast('No unrecognized lines in this session', 'info')
      } else {
        toast(`Found ${lines.length} unrecognized line(s)`, 'info')
      }
    } catch (err) {
      toast(err.message, 'error')
    } finally {
      setLoading(false)
    }
  }

  const load = (e) => {
    e?.preventDefault()
    const s = inputSession.trim()
    if (!s) return
    setSession(s)
    fetchUnrecognized(s)
  }

  const handleTrain = async (e) => {
    e.preventDefault()
    if (!selectedLine || !pattern.trim() || !category.trim()) {
      toast('Select a line and fill pattern + category', 'error')
      return
    }
    setTraining(true)
    try {
      const payload = {
        vendor: vendor.trim() || 'Cisco',
        pattern: pattern.trim(),
        security_category: category.trim(),
        control_mapping: controlMapping.split(',').map(s => s.trim()).filter(Boolean),
        remediation: remediation.trim() || `Configure ${category.trim()} properly`,
      }
      const res = await fetch(`${api}/session/${session}/train`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'training failed' }))
        throw new Error(err.error || `Training failed: ${res.status}`)
      }
      toast('Training entry added', 'success')
      // Clear form
      setSelectedLine(null)
      setPattern('')
      setCategory('')
      setControlMapping('')
      setRemediation('')
      // Re-fetch to show updated count
      const newUnrecognized = unrecognized.filter(u => u.line !== selectedLine)
      setUnrecognized(newUnrecognized)
      setTotalAfter(newUnrecognized.length)
    } catch (err) {
      toast(err.message, 'error')
    } finally {
      setTraining(false)
    }
  }

  const selectLine = (line) => {
    setSelectedLine(line)
    setPattern(line.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\.\*/g, '.*'))
    setCategory('')
    setControlMapping('')
    setRemediation('')
  }

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 8 }}>Training Loop</h1>
      <p style={{ color: 'var(--text-dim)', marginBottom: 24, fontSize: 14 }}>
        Label unrecognized config lines to teach Trinetra new patterns — no code changes required.
      </p>

      <form onSubmit={load} style={{ display: 'flex', gap: 8, marginBottom: 24 }}>
        <input
          type="text"
          value={inputSession}
          onChange={e => setInputSession(e.target.value)}
          placeholder="Session name"
          style={{ flex: 1, maxWidth: 300 }}
        />
        <button type="submit" className="btn-primary" disabled={loading || !inputSession.trim()}>
          {loading ? <><Spinner size={14} /> Loading...</> : 'Load Unrecognized Lines'}
        </button>
      </form>

      {loading && (
        <div className="empty-state card">
          <Spinner size={24} />
          <p style={{ marginTop: 12 }}>Loading unrecognized lines...</p>
        </div>
      )}

      {!loading && session && unrecognized.length === 0 && totalBefore === 0 && (
        <div className="empty-state card">
          <h3>No unrecognized lines</h3>
          <p>All config lines were recognized, or no session loaded yet.</p>
        </div>
      )}

      {!loading && unrecognized.length > 0 && (
        <div className="grid-2">
          {/* Left: unrecognized lines */}
          <div className="card" style={{ maxHeight: 500, overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <h2 style={{ fontSize: 16, fontWeight: 600 }}>Unrecognized Lines</h2>
              <span className="badge badge-review">{unrecognized.length}</span>
            </div>
            {unrecognized.map((u, i) => (
              <div
                key={i}
                className="line-item"
                style={{
                  cursor: 'pointer',
                  background: selectedLine === u.line ? 'var(--surface2)' : 'transparent',
                  borderLeft: selectedLine === u.line ? '3px solid var(--accent)' : '3px solid transparent',
                }}
                onClick={() => selectLine(u.line)}
              >
                <span style={{ fontSize: 11, color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>{u.device}</span>
                <span className="line-text">{u.line}</span>
              </div>
            ))}
          </div>

          {/* Right: training form */}
          <div className="card">
            <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>
              {selectedLine ? 'Label Selected Line' : 'Select a line to label'}
            </h2>
            {selectedLine && (
              <form onSubmit={handleTrain}>
                <div className="card" style={{ background: 'var(--surface2)', marginBottom: 16, padding: 12 }}>
                  <code style={{ fontSize: 12, wordBreak: 'break-all' }}>{selectedLine}</code>
                </div>

                <div className="form-group">
                  <label>Vendor</label>
                  <select value={vendor} onChange={e => setVendor(e.target.value)}>
                    <option value="Cisco">Cisco</option>
                    <option value="Juniper">Juniper</option>
                    <option value="Generic">Generic</option>
                  </select>
                </div>

                <div className="form-group">
                  <label>Regex Pattern (auto-generated, editable)</label>
                  <input
                    type="text"
                    value={pattern}
                    onChange={e => setPattern(e.target.value)}
                    required
                    style={{ fontFamily: 'var(--mono)', fontSize: 12 }}
                  />
                </div>

                <div className="form-group">
                  <label>Security Category</label>
                  <input
                    type="text"
                    value={category}
                    onChange={e => setCategory(e.target.value)}
                    placeholder="e.g. Access Control, Logging, Encryption"
                    required
                  />
                </div>

                <div className="form-group">
                  <label>Control Mapping (comma-separated)</label>
                  <input
                    type="text"
                    value={controlMapping}
                    onChange={e => setControlMapping(e.target.value)}
                    placeholder="e.g. CIS-v8-4.6, ISO27001-A.9"
                  />
                </div>

                <div className="form-group">
                  <label>Remediation (optional)</label>
                  <textarea
                    value={remediation}
                    onChange={e => setRemediation(e.target.value)}
                    rows={3}
                    placeholder="How to remediate this finding..."
                  />
                </div>

                <button type="submit" className="btn-primary" disabled={training} style={{ width: '100%' }}>
                  {training ? <><Spinner size={14} /> Training...</> : 'Add Training Entry'}
                </button>
              </form>
            )}
          </div>
        </div>
      )}

      {/* Before/after summary */}
      {totalBefore > 0 && (
        <div className="card" style={{ marginTop: 16 }}>
          <div style={{ display: 'flex', gap: 32, alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Before Training
              </div>
              <div style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--mono)' }}>{totalBefore}</div>
            </div>
            <div style={{ fontSize: 24, color: 'var(--text-dim)' }}>→</div>
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                After Training
              </div>
              <div style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--mono)', color: totalAfter < totalBefore ? 'var(--green)' : 'inherit' }}>
                {totalAfter || totalBefore}
              </div>
            </div>
            {totalAfter < totalBefore && (
              <span className="badge badge-pass">{totalBefore - totalAfter} line(s) trained</span>
            )}
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 12 }}>
            Training entries are stored in <code>config/vendor_training_map.json</code> and take effect on the next config upload.
            Re-upload the same config to see the corrected unrecognized count.
          </p>
        </div>
      )}
    </div>
  )
}
