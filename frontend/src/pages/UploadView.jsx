import { useState, useRef } from 'react'
import Spinner from '../components/Spinner'
import SceneHeader from '../components/SceneHeader'

const VENDORS = ['Auto-detect', 'Cisco', 'Juniper', 'Generic']
const SESSION_RE = /^[A-Za-z0-9_-]{1,64}$/
const DEVICE_RE = /^[A-Za-z0-9._-]{1,128}$/
const MAX_FILE_SIZE = 1024 * 1024 // 1MB — matches bridge limit

function SecretField({ id, label, value, onChange, placeholder, multiline = false }) {
  const [visible, setVisible] = useState(false)
  const controlProps = {
    id,
    value,
    onChange,
    placeholder,
    autoComplete: 'off',
  }

  return (
    <div className="form-group">
      <label htmlFor={id}>{label}</label>
      <div className="secret-control">
        {multiline ? (
          <textarea {...controlProps} rows={4} className={visible ? '' : 'secret-masked'} />
        ) : (
          <input {...controlProps} type={visible ? 'text' : 'password'} />
        )}
        <button
          type="button"
          className="secret-toggle"
          aria-label={`${visible ? 'Hide' : 'Show'} ${label.toLowerCase()}`}
          aria-pressed={visible}
          onClick={() => setVisible(current => !current)}
        >
          {visible ? 'Hide' : 'Show'}
        </button>
      </div>
    </div>
  )
}

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
  const [fetchSourceType, setFetchSourceType] = useState('ip')
  const [fetchTarget, setFetchTarget] = useState('')
  const [fetchUsername, setFetchUsername] = useState('')
  const [fetchPassword, setFetchPassword] = useState('')
  const [fetchSshKey, setFetchSshKey] = useState('')
  const [fetchPort, setFetchPort] = useState('22')
  const [fetchAuthToken, setFetchAuthToken] = useState('')
  const [fetchAuthHeader, setFetchAuthHeader] = useState('Authorization')
  const [errors, setErrors] = useState({})
  const abortRef = useRef(null)

  const isBulk = inputMode === 'file' && files.length > 1

  const deriveDeviceId = (fileName) => {
    // filename without extension, sanitized to DEVICE_RE-compatible
    const base = fileName.replace(/\.[^/.]+$/, '').trim()
    // replace spaces/special with hyphen, keep allowed chars
    const sanitized = base.replace(/[^A-Za-z0-9._-]/g, '-').slice(0, 64) || 'device-01'
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
    } else if (inputMode === 'text') {
      if (!configText.trim()) e.config = 'Paste config content or switch to file upload'
      if (configText.length > MAX_FILE_SIZE) e.config = `Config too large (max ${MAX_FILE_SIZE / 1024}KB)`
      const d = deviceId.trim()
      if (!d) e.deviceId = 'Device ID is required'
      else if (!DEVICE_RE.test(d)) e.deviceId = 'Only letters, numbers, dots, hyphens, underscores (max 128)'
    } else {
      const d = deviceId.trim()
      const target = fetchTarget.trim()
      if (!d) e.deviceId = 'Device ID is required for live collection'
      else if (!DEVICE_RE.test(d)) e.deviceId = 'Only letters, numbers, dots, hyphens, underscores (max 128)'
      if (!target) e.fetchTarget = fetchSourceType === 'ip' ? 'IP address or hostname is required' : 'Configuration URL is required'
      else if (fetchSourceType === 'ip' && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/.test(target)) e.fetchTarget = 'Enter a valid IP address or hostname'
      else if (fetchSourceType === 'url' && !/^https?:\/\//i.test(target)) e.fetchTarget = 'URL must start with http:// or https://'
      if (fetchSourceType === 'ip') {
        if (!fetchUsername.trim()) e.fetchUsername = 'SSH username is required'
        if (!fetchPassword && !fetchSshKey) e.fetchCredential = 'Enter an SSH password or paste a private key'
        if (!/^\d+$/.test(fetchPort) || Number(fetchPort) < 1 || Number(fetchPort) > 65535) e.fetchPort = 'Port must be between 1 and 65535'
        if (fetchPassword.length > 1024) e.fetchCredential = 'Password is too long'
        if (fetchSshKey.length > 8192) e.fetchCredential = 'Private key is too large'
      } else {
        if (fetchAuthToken.length > 2048) e.fetchCredential = 'Authentication token is too long'
        if (fetchAuthHeader && !/^[A-Za-z][A-Za-z0-9-]{0,127}$/.test(fetchAuthHeader)) e.fetchAuthHeader = 'Enter a valid HTTP header name'
      }
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

  const canSubmit = !loading && session.trim() && (
    inputMode === 'file' ? files.length > 0 :
      inputMode === 'text' ? !!configText.trim() :
        !!fetchTarget.trim() && !!deviceId.trim()
  )

  const changeInputMode = mode => {
    setInputMode(mode)
    setErrors({})
    if (mode !== 'fetch') {
      setFetchPassword('')
      setFetchSshKey('')
      setFetchAuthToken('')
    }
  }

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
        body: JSON.stringify({
          name: sessionName,
          target: inputMode === 'fetch'
            ? deviceId.trim()
            : (files[0]?.name ? deriveDeviceId(files[0].name) : deviceId.trim()) || deviceId.trim(),
        }),
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

    if (inputMode === 'fetch') {
      const timeoutId = setTimeout(() => controller.abort(), 45000)
      try {
        const body = {
          source_type: fetchSourceType,
          target: fetchTarget.trim(),
          vendor: vendorVal,
          device_id: deviceId.trim(),
          serial_number: serialVal || undefined,
          hardware_model: hardwareVal || undefined,
          os_version: osVal || undefined,
        }
        if (fetchSourceType === 'ip') {
          body.username = fetchUsername.trim()
          body.port = Number(fetchPort)
          if (fetchPassword) body.password = fetchPassword
          if (fetchSshKey) body.ssh_key = fetchSshKey
        } else {
          if (fetchAuthToken) body.auth_token = fetchAuthToken
          if (fetchAuthHeader.trim()) body.auth_header = fetchAuthHeader.trim()
        }

        const response = await fetch(`${api}/session/${encodeURIComponent(sessionName)}/fetch-config`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          signal: controller.signal,
        })
        if (!response.ok) {
          const detail = await response.json().catch(() => ({ error: 'Live collection failed' }))
          throw new Error(detail.error || `Live collection failed (${response.status})`)
        }
        const data = await response.json()
        setBulkResults([{
          fileName: `${fetchSourceType.toUpperCase()} live collection`,
          deviceId: data.device_id || deviceId.trim(),
          status: 'success',
          message: `${data.passed} passed, ${data.failed} failed, ${data.unrecognized_count} unrecognized`,
          data,
        }])
        setFetchPassword('')
        setFetchSshKey('')
        setFetchAuthToken('')
        toast('Configuration collected and scanned', 'success')
      } catch (err) {
        const message = err.name === 'AbortError' ? 'Live collection timed out. Check target reachability.' : err.message
        setBulkResults([{ fileName: 'Live collection', deviceId: deviceId.trim() || 'unknown', status: 'error', message }])
        toast(message, 'error')
      } finally {
        clearTimeout(timeoutId)
        abortRef.current = null
        setLoading(false)
      }
      return
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
          const uploadRes = await fetch(`${api}/session/${encodeURIComponent(sessionName)}/upload-config`, {
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
        uploadRes = await fetch(`${api}/session/${encodeURIComponent(sessionName)}/upload-config`, {
          method: 'POST',
          body: form,
          signal: controller.signal,
        })
      } else {
        uploadRes = await fetch(`${api}/session/${encodeURIComponent(sessionName)}/upload-config`, {
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
      <SceneHeader
        index="01"
        label="Ingest"
        title="Upload Device Config"
        description="Upload single or bulk device configs. For bulk, select multiple files — each filename becomes a device ID and gets ingested sequentially with per-file status."
      />

      <form onSubmit={handleSubmit} noValidate>
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

        <fieldset className="form-group choice-fieldset">
          <legend>Vendor</legend>
          <div className="vendor-options">
            {VENDORS.map(v => (
              <label className={`vendor-option${vendor === v ? ' is-selected' : ''}`} key={v}>
                <input
                  type="radio"
                  name="vendor"
                  value={v}
                  checked={vendor === v}
                  onChange={e => setVendor(e.target.value)}
                />
                <span className="choice-control" aria-hidden="true" />
                <span className="vendor-name">{v}</span>
              </label>
            ))}
          </div>
          <p className="field-help">Use auto-detect unless the configuration source is already known.</p>
        </fieldset>

        <div className="card" style={{ padding: 16, marginBottom: 16 }}>
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
          <div className="input-mode-switch">
            <button
              type="button"
              className={`btn-secondary ${inputMode === 'file' ? 'btn-primary' : ''}`}
              onClick={() => changeInputMode('file')}
            >
              File Upload {files.length > 1 ? `(${files.length} files)` : ''}
            </button>
            <button
              type="button"
              className={`btn-secondary ${inputMode === 'text' ? 'btn-primary' : ''}`}
              onClick={() => changeInputMode('text')}
            >
              Paste Config
            </button>
            <button
              type="button"
              className={`btn-secondary ${inputMode === 'fetch' ? 'btn-primary' : ''}`}
              onClick={() => changeInputMode('fetch')}
            >
              Collect from Network
            </button>
          </div>
          <p className="field-help">File upload is recommended. Live collection requires direct network access from the Cortex bridge.</p>
        </div>

        {inputMode === 'file' ? (
          <div className="form-group">
            <label>Config File(s) — bulk supported (select multiple)</label>
            <input
              type="file"
              onChange={handleFilesChange}
              accept=".txt,.cfg,.conf,.log,.xml,.json,.csv"
              multiple
            />
            {files.length > 0 && (
              <div style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 6 }}>
                Selected: {files.map(f => `${f.name} (${(f.size / 1024).toFixed(1)} KB)`).join(', ')}
                {files.length > 1 && <span style={{ marginLeft: 8, color: 'var(--accent)' }}>Bulk mode: {files.length} devices, each filename → device ID, sequential ingestion with per-file status below.</span>}
              </div>
            )}
            {errors.config && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 4 }}>{errors.config}</div>}
          </div>
        ) : inputMode === 'text' ? (
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
        ) : (
          <section className="fetch-panel" aria-labelledby="fetch-heading">
            <div className="fetch-heading-row">
              <div>
                <span className="benchmark-eyebrow">Optional source</span>
                <h2 id="fetch-heading">Live configuration collection</h2>
              </div>
              <span className="fetch-security-note">Credentials are never stored</span>
            </div>

            <div className="source-type-switch" aria-label="Collection source">
              <button
                type="button"
                className={fetchSourceType === 'ip' ? 'is-selected' : ''}
                aria-pressed={fetchSourceType === 'ip'}
                onClick={() => { setFetchSourceType('ip'); setErrors({}) }}
              >
                SSH device
              </button>
              <button
                type="button"
                className={fetchSourceType === 'url' ? 'is-selected' : ''}
                aria-pressed={fetchSourceType === 'url'}
                onClick={() => { setFetchSourceType('url'); setErrors({}) }}
              >
                HTTPS endpoint
              </button>
            </div>

            <div className="form-group">
              <label htmlFor="fetch-target">{fetchSourceType === 'ip' ? 'IP address or hostname' : 'Configuration URL'}</label>
              <input
                id="fetch-target"
                type={fetchSourceType === 'url' ? 'url' : 'text'}
                value={fetchTarget}
                onChange={e => { setFetchTarget(e.target.value); setErrors(prev => ({ ...prev, fetchTarget: null })) }}
                placeholder={fetchSourceType === 'ip' ? '10.0.0.1 or edge-router.local' : 'https://example.com/export/config'}
                aria-invalid={Boolean(errors.fetchTarget)}
                aria-describedby={errors.fetchTarget ? 'fetch-target-error' : undefined}
              />
              {errors.fetchTarget && <div id="fetch-target-error" className="field-error">{errors.fetchTarget}</div>}
            </div>

            {fetchSourceType === 'ip' ? (
              <>
                <div className="grid-2">
                  <div className="form-group">
                    <label htmlFor="fetch-username">SSH username</label>
                    <input
                      id="fetch-username"
                      type="text"
                      value={fetchUsername}
                      onChange={e => { setFetchUsername(e.target.value); setErrors(prev => ({ ...prev, fetchUsername: null })) }}
                      placeholder="admin"
                      autoComplete="username"
                      aria-invalid={Boolean(errors.fetchUsername)}
                    />
                    {errors.fetchUsername && <div className="field-error">{errors.fetchUsername}</div>}
                  </div>
                  <div className="form-group">
                    <label htmlFor="fetch-port">SSH port</label>
                    <input
                      id="fetch-port"
                      type="number"
                      min="1"
                      max="65535"
                      inputMode="numeric"
                      value={fetchPort}
                      onChange={e => { setFetchPort(e.target.value); setErrors(prev => ({ ...prev, fetchPort: null })) }}
                      aria-invalid={Boolean(errors.fetchPort)}
                    />
                    {errors.fetchPort && <div className="field-error">{errors.fetchPort}</div>}
                  </div>
                </div>
                <div className="grid-2">
                  <SecretField
                    id="fetch-password"
                    label="SSH password"
                    value={fetchPassword}
                    onChange={e => { setFetchPassword(e.target.value); setErrors(prev => ({ ...prev, fetchCredential: null })) }}
                    placeholder="Enter password"
                  />
                  <SecretField
                    id="fetch-key"
                    label="Private key (PEM)"
                    value={fetchSshKey}
                    onChange={e => { setFetchSshKey(e.target.value); setErrors(prev => ({ ...prev, fetchCredential: null })) }}
                    placeholder="Paste private key content"
                    multiline
                  />
                </div>
                {errors.fetchCredential && <div className="field-error">{errors.fetchCredential}</div>}
                <p className="fetch-detail">SSH host-key verification uses the bridge machine’s known_hosts file. Cortex will not automatically trust an unknown device.</p>
              </>
            ) : (
              <div className="grid-2">
                <SecretField
                  id="fetch-token"
                  label="Authentication token (optional)"
                  value={fetchAuthToken}
                  onChange={e => { setFetchAuthToken(e.target.value); setErrors(prev => ({ ...prev, fetchCredential: null })) }}
                  placeholder="Bearer token"
                />
                <div className="form-group">
                  <label htmlFor="fetch-header">Authentication header</label>
                  <input
                    id="fetch-header"
                    type="text"
                    value={fetchAuthHeader}
                    onChange={e => { setFetchAuthHeader(e.target.value); setErrors(prev => ({ ...prev, fetchAuthHeader: null })) }}
                    placeholder="Authorization"
                    aria-invalid={Boolean(errors.fetchAuthHeader)}
                  />
                  {errors.fetchAuthHeader && <div className="field-error">{errors.fetchAuthHeader}</div>}
                </div>
              </div>
            )}
          </section>
        )}

        <button type="submit" className="btn-primary" disabled={!canSubmit} style={{ marginTop: 8 }}>
          {loading ? <><Spinner size={14} /> {isBulk ? `Uploading bulk (${bulkResults.filter(r=>r.status==='success').length}/${files.length})...` : inputMode === 'fetch' ? 'Collecting & scanning...' : 'Processing...'} </> : isBulk ? `Run Bulk Compliance Scan (${files.length} files)` : inputMode === 'fetch' ? 'Collect & Scan' : 'Run Compliance Scan'}
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
              href={`${api}/session/${encodeURIComponent(session.trim())}/audit-report/pdf`}
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
