import { useState, useRef } from 'react'
import Spinner from '../components/Spinner'

const VENDORS = ['Auto-detect', 'Cisco', 'Juniper', 'Generic']
const SESSION_RE = /^[A-Za-z0-9_\-]{1,64}$/
const DEVICE_RE = /^[A-Za-z0-9._\-]{1,128}$/
const MAX_FILE_SIZE = 1024 * 1024 // 1MB — matches bridge limit

export default function UploadView({ api, toast }) {
  const [session, setSession] = useState('')
  const [deviceId, setDeviceId] = useState('')
  const [vendor, setVendor] = useState('Auto-detect')
  const [file, setFile] = useState(null)
  const [configText, setConfigText] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [inputMode, setInputMode] = useState('file')
  const [errors, setErrors] = useState({})
  const abortRef = useRef(null)

  const validate = () => {
    const e = {}
    const s = session.trim()
    const d = deviceId.trim()
    if (!s) e.session = 'Session name is required'
    else if (!SESSION_RE.test(s)) e.session = 'Only letters, numbers, hyphens, underscores (max 64)'
    if (!d) e.deviceId = 'Device ID is required'
    else if (!DEVICE_RE.test(d)) e.deviceId = 'Only letters, numbers, dots, hyphens, underscores (max 128)'
    if (inputMode === 'file' && !file) e.config = 'Select a config file'
    if (inputMode === 'text' && !configText.trim()) e.config = 'Paste config content or switch to file upload'
    if (inputMode === 'text' && configText.length > MAX_FILE_SIZE) e.config = `Config too large (max ${MAX_FILE_SIZE / 1024}KB)`
    if (inputMode === 'file' && file && file.size > MAX_FILE_SIZE) e.config = `File too large (max ${MAX_FILE_SIZE / 1024}KB)`
    setErrors(e)
    return Object.keys(e).length === 0
  }

  const canSubmit = !loading && session.trim() && deviceId.trim() && (inputMode === 'file' ? !!file : !!configText.trim())

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!validate()) return

    setLoading(true)
    setResult(null)
    setErrors({})

    // 60s timeout matching bridge SUBPROCESS_TIMEOUT
    const controller = new AbortController()
    abortRef.current = controller
    const timeoutId = setTimeout(() => controller.abort(), 60000)

    try {
      const sessionName = session.trim()
      const devId = deviceId.trim()
      const vendorVal = vendor === 'Auto-detect' ? 'auto' : vendor

      // Step 1: Create session (ignore 409 = already exists)
      const createRes = await fetch(`${api}/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: sessionName, target: devId }),
        signal: controller.signal,
      })
      if (!createRes.ok && createRes.status !== 409) {
        const err = await createRes.json().catch(() => ({ error: 'session create failed' }))
        throw new Error(err.error || `Session create failed (${createRes.status})`)
      }

      // Step 2: Upload config
      let uploadRes
      if (file) {
        const form = new FormData()
        form.append('device_id', devId)
        form.append('vendor', vendorVal)
        form.append('config', file)
        uploadRes = await fetch(`${api}/session/${sessionName}/upload-config`, {
          method: 'POST',
          body: form,
          signal: controller.signal,
        })
      } else {
        uploadRes = await fetch(`${api}/session/${sessionName}/upload-config`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            device_id: devId,
            vendor: vendorVal,
            config_content: configText,
            filename: `${devId}_config.txt`,
          }),
          signal: controller.signal,
        })
      }

      if (!uploadRes.ok) {
        const err = await uploadRes.json().catch(() => ({ error: 'upload failed' }))
        throw new Error(err.error || `Upload failed (${uploadRes.status})`)
      }

      const data = await uploadRes.json()
      setResult(data)
      toast(`Config ingested: ${data.passed} passed, ${data.failed} failed, ${data.unrecognized_count} unrecognized`, 'success')
    } catch (err) {
      if (err.name === 'AbortError') {
        toast('Request timed out (60s). The bridge may be unreachable.', 'error')
      } else {
        toast(err.message, 'error')
      }
    } finally {
      clearTimeout(timeoutId)
      abortRef.current = null
      setLoading(false)
    }
  }

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 8 }}>Upload Device Config</h1>
      <p style={{ color: 'var(--text-dim)', marginBottom: 24, fontSize: 14 }}>
        Upload a network device configuration file for compliance scanning.
      </p>

      <form onSubmit={handleSubmit}>
        <div className="grid-2">
          <div className="form-group">
            <label>Session Name</label>
            <input
              type="text"
              value={session}
              onChange={e => { setSession(e.target.value); setErrors(prev => ({ ...prev, session: null })) }}
              placeholder="e.g. demo, prod-audit-01"
            />
            {errors.session && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 4 }}>{errors.session}</div>}
          </div>
          <div className="form-group">
            <label>Device ID</label>
            <input
              type="text"
              value={deviceId}
              onChange={e => { setDeviceId(e.target.value); setErrors(prev => ({ ...prev, deviceId: null })) }}
              placeholder="e.g. cisco-01, 10.0.0.1"
            />
            {errors.deviceId && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 4 }}>{errors.deviceId}</div>}
          </div>
        </div>

        <div className="form-group">
          <label>Vendor</label>
          <select value={vendor} onChange={e => setVendor(e.target.value)}>
            {VENDORS.map(v => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>

        <div className="form-group">
          <label>Input Method</label>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            <button
              type="button"
              className={`btn-secondary ${inputMode === 'file' ? 'btn-primary' : ''}`}
              onClick={() => setInputMode('file')}
            >
              File Upload
            </button>
            <button
              type="button"
              className={`btn-secondary ${inputMode === 'text' ? 'btn-primary' : ''}`}
              onClick={() => setInputMode('text')}
            >
              Paste Config
            </button>
          </div>
        </div>

        {inputMode === 'file' ? (
          <div className="form-group">
            <label>Config File</label>
            <input
              type="file"
              onChange={e => { setFile(e.target.files[0]); setErrors(prev => ({ ...prev, config: null })) }}
              accept=".txt,.cfg,.conf,.log,.xml,.json,.csv"
              style={{ padding: '6px 0' }}
            />
            {file && (
              <p style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 6 }}>
                Selected: {file.name} ({(file.size / 1024).toFixed(1)} KB)
              </p>
            )}
            {errors.config && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 4 }}>{errors.config}</div>}
          </div>
        ) : (
          <div className="form-group">
            <label>Configuration Content</label>
            <textarea
              value={configText}
              onChange={e => { setConfigText(e.target.value); setErrors(prev => ({ ...prev, config: null })) }}
              rows={10}
              placeholder={`hostname R1\nenable secret 5 $1$...\nline vty 0 4\n no exec-timeout\n logging synchronous\n exit`}
              style={{ fontFamily: 'var(--mono)', fontSize: 13 }}
            />
            {errors.config && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 4 }}>{errors.config}</div>}
          </div>
        )}

        <button type="submit" className="btn-primary" disabled={!canSubmit} style={{ marginTop: 8 }}>
          {loading ? <><Spinner size={14} /> Processing...</> : 'Run Compliance Scan'}
        </button>
      </form>

      {result && (
        <div className="card" style={{ marginTop: 24 }}>
          <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>Scan Results</h2>
          <div className="stat-grid">
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--green)' }}>{result.passed}</div>
              <div className="stat-label">Passed</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--red)' }}>{result.failed}</div>
              <div className="stat-label">Failed</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{result.total_checks}</div>
              <div className="stat-label">Total Checks</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--yellow)' }}>{result.unrecognized_count}</div>
              <div className="stat-label">Unrecognized</div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 12, marginTop: 16, flexWrap: 'wrap' }}>
            <a href={`/results?session=${session.trim()}`} className="btn-primary" style={{ display: 'inline-block' }}>
              View Detailed Results
            </a>
            <a href={`/devices?session=${session.trim()}`} className="btn-secondary" style={{ display: 'inline-block' }}>
              View Session Devices
            </a>
            <a href={`/training?session=${session.trim()}`} className="btn-secondary" style={{ display: 'inline-block' }}>
              {result.unrecognized_count > 0 ? `Train Unrecognized (${result.unrecognized_count})` : 'Training View'}
            </a>
            <a
              href={`${api}/session/${session.trim()}/audit-report/pdf`}
              className="btn-secondary"
              style={{ display: 'inline-block' }}
              target="_blank"
              rel="noopener noreferrer"
            >
              Download PDF
            </a>
          </div>
        </div>
      )}
    </div>
  )
}
