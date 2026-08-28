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
  const [serialNumber, setSerialNumber] = useState('')
  const [hardwareModel, setHardwareModel] = useState('')
  const [osVersion, setOsVersion] = useState('')
  const [files, setFiles] = useState([])
  const [configText, setConfigText] = useState('')
  const [loading, setLoading] = useState(false)
  const [bulkResults, setBulkResults] = useState([]) // per-file {fileName, deviceId, status, message, data}
  const [inputMode, setInputMode] = useState('file')
  const [errors, setErrors] = useState({})
  const abortRef = useRef(null)

  const isBulk = inputMode === 'file' && files.length > 1

  const deriveDeviceId = (fileName) => {
    // filename without extension, sanitized to DEVICE_RE-compatible
    const base = fileName.replace(/\.[^/.]+$/, '').trim()
    // replace spaces/special with hyphen, keep allowed chars
    const sanitized = base.replace(/[^A-Za-z0-9._\-]/g, '-').slice(0, 64) || 'device-01'
    return sanitized
  }

  const validate = () => {
    const e = {}
    const s = session.trim()
    if (!s) e.session = 'Session name is required'
    else if (!SESSION_RE.test(s)) e.session = 'Only letters, numbers, hyphens, underscores (max 64)'
    if (inputMode === 'file') {
      if (files.length === 0) e.config = 'Select at least one config file'
      else {
        for (const f of files) {
          if (f.size > MAX_FILE_SIZE) { e.config = `File ${f.name} too large (max ${MAX_FILE_SIZE / 1024}KB)`; break }
        }
      }
      // For single-file mode, deviceId field is required; for bulk, deviceIds derived from filenames so not required
      if (files.length === 1) {
        const d = deviceId.trim()
        if (!d) e.deviceId = 'Device ID is required for single-file upload'
        else if (!DEVICE_RE.test(d)) e.deviceId = 'Only letters, numbers, dots, hyphens, underscores (max 128)'
      }
    } else {
      if (!configText.trim()) e.config = 'Paste config content or switch to file upload'
      if (configText.length > MAX_FILE_SIZE) e.config = `Config too large (max ${MAX_FILE_SIZE / 1024}KB)`
      const d = deviceId.trim()
      if (!d) e.deviceId = 'Device ID is required'
      else if (!DEVICE_RE.test(d)) e.deviceId = 'Only letters, numbers, dots, hyphens, underscores (max 128)'
    }
    // Optional hardware fields validation (no injection, max 128)
    for (const [key, val] of [['serialNumber', serialNumber], ['hardwareModel', hardwareModel], ['osVersion', osVersion]]) {
      if (val && val.length > 128) e[key] = 'Max 128 characters'
      if (val && /[;|&$`><\\'"*\n\r]/.test(val)) e[key] = 'Illegal characters'
    }
    setErrors(e)
    return Object.keys(e).length === 0
  }

  const handleFilesChange = (e) => {
    const list = Array.from(e.target.files || [])
    setFiles(list)
    setBulkResults([])
    setErrors(prev => ({ ...prev, config: null }))
  }

  const canSubmit = !loading && session.trim() && (inputMode === 'file' ? files.length > 0 : !!configText.trim())

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!validate()) return

    setLoading(true)
    setBulkResults([])
    setErrors({})

    const controller = new AbortController()
    abortRef.current = controller

    const sessionName = session.trim()
    const vendorVal = vendor === 'Auto-detect' ? 'auto' : vendor
    const serialVal = serialNumber.trim()
    const hardwareVal = hardwareModel.trim()
    const osVal = osVersion.trim()

    // Step 1: Create session (ignore 409 = already exists)
    try {
      const createRes = await fetch(`${api}/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: sessionName, target: (files[0]?.name ? deriveDeviceId(files[0].name) : deviceId.trim()) || deviceId.trim() }),
        signal: controller.signal,
      })
      if (!createRes.ok && createRes.status !== 409) {
        const err = await createRes.json().catch(() => ({ error: 'session create failed' }))
        throw new Error(err.error || `Session create failed (${createRes.status})`)
      }
    } catch (err) {
      if (err.name === 'AbortError') { toast('Request timed out (60s). The bridge may be unreachable.', 'error'); setLoading(false); return }
      // Non-fatal for session create 409 case already handled; other errors still fatal
      if (!err.message.includes('already exists')) {
        toast(err.message, 'error')
        setLoading(false)
        return
      }
    }

    // Step 2: Upload — bulk sequential (choice A) to reuse single-upload endpoint and show per-file status
    // Why sequential (a) over bulk endpoint (b): reuses proven ingestion path, per-file vendor auto-detect, atomic per-file error visibility, no new backend route, dashboard aggregation already works via sequential devices.
    if (inputMode === 'file' && files.length > 1) {
      const results = files.map(f => ({ fileName: f.name, deviceId: deriveDeviceId(f.name), status: 'pending', message: '' }))
      setBulkResults([...results])
      let successCount = 0
      let failCount = 0
      for (let idx = 0; idx < files.length; idx++) {
        const f = files[idx]
        const did = deriveDeviceId(f.name)
        // Mark uploading
        results[idx] = { ...results[idx], status: 'uploading', message: 'Uploading...' }
        setBulkResults([...results])
        try {
          const timeoutId = setTimeout(() => controller.abort(), 60000)
          const form = new FormData()
          form.append('device_id', did)
          form.append('vendor', vendorVal)
          if (serialVal) form.append('serial_number', serialVal)
          if (hardwareVal) form.append('hardware_model', hardwareVal)
          if (osVal) form.append('os_version', osVal)
          form.append('config', f)
          const uploadRes = await fetch(`${api}/session/${sessionName}/upload-config`, {
            method: 'POST',
            body: form,
            signal: controller.signal,
          })
          clearTimeout(timeoutId)
          if (!uploadRes.ok) {
            const err = await uploadRes.json().catch(() => ({ error: 'upload failed' }))
            throw new Error(err.error || `Upload failed (${uploadRes.status})`)
          }
          const data = await uploadRes.json()
          results[idx] = { fileName: f.name, deviceId: did, status: 'success', message: `${data.passed} passed, ${data.failed} failed, ${data.unrecognized_count} unrecognized`, data }
          successCount++
          toast(`[${f.name}] ingested: ${data.passed} passed`, 'success')
        } catch (err) {
          const msg = err.name === 'AbortError' ? 'timed out (60s)' : err.message
          results[idx] = { fileName: f.name, deviceId: did, status: 'error', message: msg }
          failCount++
          toast(`[${f.name}] failed: ${msg}`, 'error')
        }
        setBulkResults([...results])
      }
      setLoading(false)
      abortRef.current = null
      if (successCount > 0) {
        toast(`Bulk complete: ${successCount} succeeded, ${failCount} failed — see Session Devices`, 'info')
      }
      return
    }

    // Single-file or paste path
    const timeoutId = setTimeout(() => controller.abort(), 60000)
    try {
      const devId = inputMode === 'file' ? (files.length === 1 ? deviceId.trim() : deriveDeviceId(files[0]?.name || 'device-01')) : deviceId.trim()
      let uploadRes
      if (inputMode === 'file' && files.length === 1) {
        const form = new FormData()
        form.append('device_id', devId)
        form.append('vendor', vendorVal)
        if (serialVal) form.append('serial_number', serialVal)
        if (hardwareVal) form.append('hardware_model', hardwareVal)
        if (osVal) form.append('os_version', osVal)
        form.append('config', files[0])
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
            serial_number: serialVal || undefined,
            hardware_model: hardwareVal || undefined,
            os_version: osVal || undefined,
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
      setBulkResults([{ fileName: devId, deviceId: devId, status: 'success', message: `${data.passed} passed, ${data.failed} failed, ${data.unrecognized_count} unrecognized`, data }])
      toast(`Config ingested: ${data.passed} passed, ${data.failed} failed, ${data.unrecognized_count} unrecognized`, 'success')
    } catch (err) {
      if (err.name === 'AbortError') {
        toast('Request timed out (60s). The bridge may be unreachable.', 'error')
      } else {
        toast(err.message, 'error')
      }
      setBulkResults([{ fileName: deviceId.trim() || 'config', deviceId: deviceId.trim() || 'unknown', status: 'error', message: err.message }])
    } finally {
      clearTimeout(timeoutId)
      abortRef.current = null
      setLoading(false)
    }
  }

  const hasResults = bulkResults.length > 0
  const successResults = bulkResults.filter(r => r.status === 'success')

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 8 }}>Upload Device Config</h1>
      <p style={{ color: 'var(--text-dim)', marginBottom: 24, fontSize: 14 }}>
        Upload single or bulk device configs. For bulk, select multiple files — each filename becomes a device ID and gets ingested sequentially with per-file status.
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
            <label>Device ID {isBulk && <span style={{ fontWeight: 400, color: 'var(--text-dim)' }}>(auto-derived from filenames in bulk)</span>}</label>
            <input
              type="text"
              value={deviceId}
              onChange={e => { setDeviceId(e.target.value); setErrors(prev => ({ ...prev, deviceId: null })) }}
              placeholder={isBulk ? 'ignored in bulk — derived from filename' : 'e.g. cisco-01, 10.0.0.1'}
              disabled={isBulk}
              style={isBulk ? { opacity: 0.6 } : undefined}
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

        <div className="card" style={{ background: 'var(--surface2)', padding: 16, marginBottom: 16 }}>
          <label style={{ fontWeight: 600, marginBottom: 8 }}>Distinct Hardware Fields (optional, per PS Deliverable 4)</label>
          <div className="grid-2">
            <div className="form-group">
              <label>Serial Number</label>
              <input type="text" value={serialNumber} onChange={e => { setSerialNumber(e.target.value); setErrors(prev => ({ ...prev, serialNumber: null })) }} placeholder="e.g. FTX12345678" />
              {errors.serialNumber && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 4 }}>{errors.serialNumber}</div>}
            </div>
            <div className="form-group">
              <label>Hardware Model</label>
              <input type="text" value={hardwareModel} onChange={e => { setHardwareModel(e.target.value); setErrors(prev => ({ ...prev, hardwareModel: null })) }} placeholder="e.g. C9300-48P, SRX345" />
              {errors.hardwareModel && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 4 }}>{errors.hardwareModel}</div>}
            </div>
          </div>
          <div className="form-group">
            <label>OS Version {osVersion === '' && <span style={{ fontWeight: 400, color: 'var(--text-dim)' }}>(auto-detected from config header if blank — IOS XE / NX-OS / JUNOS)</span>}</label>
            <input type="text" value={osVersion} onChange={e => { setOsVersion(e.target.value); setErrors(prev => ({ ...prev, osVersion: null })) }} placeholder="e.g. IOS XE 17.6.5 or blank for auto-detect" />
            {errors.osVersion && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 4 }}>{errors.osVersion}</div>}
          </div>
        </div>

        <div className="form-group">
          <label>Input Method</label>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            <button
              type="button"
              className={`btn-secondary ${inputMode === 'file' ? 'btn-primary' : ''}`}
              onClick={() => setInputMode('file')}
            >
              File Upload {files.length > 1 ? `(${files.length} files)` : ''}
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
            <label>Config File(s) — bulk supported (select multiple)</label>
            <input
              type="file"
              onChange={handleFilesChange}
              accept=".txt,.cfg,.conf,.log,.xml,.json,.csv"
              multiple
              style={{ padding: '6px 0' }}
            />
            {files.length > 0 && (
              <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 6 }}>
                Selected: {files.map(f => `${f.name} (${(f.size / 1024).toFixed(1)} KB)`).join(', ')}
                {files.length > 1 && <span style={{ marginLeft: 8, color: 'var(--accent)' }}>Bulk mode: {files.length} devices, each filename → device ID, sequential ingestion with per-file status below.</span>}
              </div>
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
          {loading ? <><Spinner size={14} /> {isBulk ? `Uploading bulk (${bulkResults.filter(r=>r.status==='success').length}/${files.length})...` : 'Processing...'} </> : isBulk ? `Run Bulk Compliance Scan (${files.length} files)` : 'Run Compliance Scan'}
        </button>
      </form>

      {hasResults && (
        <div className="card" style={{ marginTop: 24 }}>
          <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>{isBulk || bulkResults.length > 1 ? 'Bulk Scan Results (per-file)' : 'Scan Results'}</h2>
          {bulkResults.length === 1 && bulkResults[0].data ? (
            <div className="stat-grid">
              <div className="stat-card">
                <div className="stat-value" style={{ color: 'var(--green)' }}>{bulkResults[0].data.passed}</div>
                <div className="stat-label">Passed</div>
              </div>
              <div className="stat-card">
                <div className="stat-value" style={{ color: 'var(--red)' }}>{bulkResults[0].data.failed}</div>
                <div className="stat-label">Failed</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">{bulkResults[0].data.total_checks}</div>
                <div className="stat-label">Total Checks</div>
              </div>
              <div className="stat-card">
                <div className="stat-value" style={{ color: 'var(--yellow)' }}>{bulkResults[0].data.unrecognized_count}</div>
                <div className="stat-label">Unrecognized</div>
              </div>
            </div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>File / Device</th>
                    <th>Status</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {bulkResults.map((r, i) => (
                    <tr key={i}>
                      <td style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{r.fileName}<div style={{ fontSize: 11, color: 'var(--text-dim)' }}>{r.deviceId}</div></td>
                      <td>
                        {r.status === 'pending' && <span className="badge" style={{ background: '#e5e7eb' }}>pending</span>}
                        {r.status === 'uploading' && <span className="badge badge-review"><Spinner size={10} /> uploading</span>}
                        {r.status === 'success' && <span className="badge badge-pass">success</span>}
                        {r.status === 'error' && <span className="badge badge-fail">failed</span>}
                      </td>
                      <td style={{ fontSize: 12 }}>{r.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div style={{ display: 'flex', gap: 12, marginTop: 16, flexWrap: 'wrap' }}>
            <a href={`/results?session=${session.trim()}`} className="btn-primary" style={{ display: 'inline-block' }}>
              View Detailed Results {successResults.length > 0 ? `(${successResults.length} devices)` : ''}
            </a>
            <a href={`/devices?session=${session.trim()}`} className="btn-secondary" style={{ display: 'inline-block' }}>
              View Session Devices
            </a>
            <a href={`/training?session=${session.trim()}`} className="btn-secondary" style={{ display: 'inline-block' }}>
              Training View
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
          {isBulk && <p style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 12 }}>All bulk devices appear in <a href={`/devices?session=${session.trim()}`}>Session Devices</a> dashboard — confirms Prompt 23 dashboard accumulates sequential bulk uploads.</p>}
        </div>
      )}
    </div>
  )
}
