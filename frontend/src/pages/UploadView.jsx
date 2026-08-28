import { useState } from 'react'
import Spinner from '../components/Spinner'

const VENDORS = ['Auto-detect', 'Cisco', 'Juniper', 'Generic']

export default function UploadView({ api, toast }) {
  const [session, setSession] = useState('')
  const [deviceId, setDeviceId] = useState('')
  const [vendor, setVendor] = useState('Auto-detect')
  const [file, setFile] = useState(null)
  const [configText, setConfigText] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [inputMode, setInputMode] = useState('file')

  const canSubmit = (session.trim() && deviceId.trim() && (file || configText.trim())) && !loading

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!canSubmit) return
    setLoading(true)
    setResult(null)

    try {
      const sessionName = session.trim()
      const devId = deviceId.trim()
      const vendorVal = vendor === 'Auto-detect' ? 'auto' : vendor

      // Step 1: Create session
      const createRes = await fetch(`${api}/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: sessionName, target: devId }),
      })
      if (!createRes.ok) {
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
      toast(err.message, 'error')
    } finally {
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
              onChange={e => setSession(e.target.value)}
              placeholder="e.g. demo, prod-audit-01"
              required
            />
          </div>
          <div className="form-group">
            <label>Device ID</label>
            <input
              type="text"
              value={deviceId}
              onChange={e => setDeviceId(e.target.value)}
              placeholder="e.g. cisco-01, 10.0.0.1"
              required
            />
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
              onChange={e => setFile(e.target.files[0])}
              accept=".txt,.cfg,.conf,.log,.xml,.json,.csv"
              style={{ padding: '6px 0' }}
            />
            {file && (
              <p style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 6 }}>
                Selected: {file.name} ({(file.size / 1024).toFixed(1)} KB)
              </p>
            )}
          </div>
        ) : (
          <div className="form-group">
            <label>Configuration Content</label>
            <textarea
              value={configText}
              onChange={e => setConfigText(e.target.value)}
              rows={10}
              placeholder={`hostname R1\nenable secret 5 $1$...\nline vty 0 4\n no exec-timeout\n logging synchronous\n exit`}
              style={{ fontFamily: 'var(--mono)', fontSize: 13 }}
            />
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

          <div style={{ display: 'flex', gap: 12, marginTop: 16 }}>
            <a href={`/results?session=${session.trim()}`} className="btn-primary" style={{ display: 'inline-block' }}>
              View Detailed Results
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
