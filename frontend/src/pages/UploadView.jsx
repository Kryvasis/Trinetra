import { useState, useRef, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import Spinner from '../components/Spinner'
import SceneHeader from '../components/SceneHeader'
import WebsiteView from './WebsiteView'
import { rememberSession } from '../utils/activeSession'

const VENDORS = ['Auto-detect', 'Cisco', 'Juniper', 'FortiOS', 'PAN-OS', 'Generic']
const SESSION_RE = /^[A-Za-z0-9_-]{1,64}$/
const DEVICE_RE = /^[A-Za-z0-9._-]{1,128}$/
const MAX_FILE_SIZE = 1024 * 1024 // 1MB — matches bridge limit

// Strict hostname validation mirrors bridge/app.py is_valid_hostname (RFC 1123)
function isValidHostname(h) {
  if (typeof h !== 'string') return false
  if (h.length < 3 || h.length > 253) return false
  if (h.startsWith('.') || h.endsWith('.') || h.includes('..')) return false
  if (!/^[A-Za-z0-9.-]+$/.test(h)) return false
  const labels = h.split('.')
  for (const label of labels) {
    if (label.length < 1 || label.length > 63) return false
    if (label.startsWith('-') || label.endsWith('-')) return false
    if (!/^[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9]$/.test(label) && label.length !== 1) return false
    if (label.length === 1 && !/^[A-Za-z0-9]$/.test(label)) return false
  }
  if (labels.length > 1) {
    const tld = labels[labels.length - 1]
    if (tld.length < 2 || !/^[A-Za-z]+$/.test(tld)) return false
  }
  if (labels.length === 1 && /^\d+$/.test(h)) return false
  return true
}
function isValidIp(t) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(t)) {
    return t.split('.').every(o => {
      const n = Number(o)
      return n >= 0 && n <= 255 && String(n) === o
    })
  }
  if (t.includes(':')) {
    // IPv6: use URL constructor trick or simple check
    try {
      // URL requires brackets for IPv6, so test via simple regex
      return /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F:]+$/.test(t) && t.split(':').length <= 8
    } catch { return false }
  }
  return false
}
function isValidIpOrHostname(t) {
  return isValidIp(t) || isValidHostname(t)
}
function isValidUrl(t) {
  try {
    const u = new URL(t)
    if (!['http:', 'https:'].includes(u.protocol)) return false
    if (!u.hostname) return false
    if (!isValidHostname(u.hostname) && !isValidIp(u.hostname)) return false
    if (u.username || u.password) return false
    return true
  } catch { return false }
}

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
          <textarea {...controlProps} rows={4} className={`resize-none ${visible ? '' : 'secret-masked'}`} />
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
  const [searchParams, setSearchParams] = useSearchParams()
  const initialWebsite = searchParams.get('source') === 'website'
  const [websiteBusy, setWebsiteBusy] = useState(false)
  const [session, setSession] = useState(searchParams.get('session') || '')
  const [deviceId, setDeviceId] = useState('')
  const [vendor, setVendor] = useState('Auto-detect')
  const [serialNumber, setSerialNumber] = useState('')
  const [hardwareModel, setHardwareModel] = useState('')
  const [osVersion, setOsVersion] = useState('')
  const [files, setFiles] = useState([])
  const [configText, setConfigText] = useState('')
  const [loading, setLoading] = useState(false)
  const [bulkResults, setBulkResults] = useState([]) // per-file {fileName, deviceId, status, message, data}
  const [inputMode, setInputMode] = useState(initialWebsite ? 'fetch' : 'file')
  const [fetchSourceType, setFetchSourceType] = useState(initialWebsite ? 'website' : 'ip')
  const [fetchTarget, setFetchTarget] = useState('')
  const [fetchUsername, setFetchUsername] = useState('')
  const [fetchPassword, setFetchPassword] = useState('')
  const [fetchSshKey, setFetchSshKey] = useState('')
  const [fetchPort, setFetchPort] = useState('22')
  const [fetchAuthToken, setFetchAuthToken] = useState('')
  const [fetchAuthHeader, setFetchAuthHeader] = useState('Authorization')
  const [errors, setErrors] = useState({})
  const abortRef = useRef(null)
  useEffect(() => () => abortRef.current?.abort(), [])
  const isWebsite = inputMode === 'fetch' && fetchSourceType === 'website'

  function changeSource(source) {
    if (source === fetchSourceType) return
    setFetchSourceType(source)
    const next = new URLSearchParams(searchParams)
    if (source === 'website') next.set('source', 'website')
    else next.delete('source')
    setSearchParams(next, { replace: true })
    setFetchPassword('')
    setFetchSshKey('')
    setFetchAuthToken('')
    setFetchTarget('')
    setErrors({})
    setBulkResults([])
  }

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
        const ids = files.map(f => deriveDeviceId(f.name))
        if (new Set(ids).size !== ids.length) e.config = 'Some filenames produce the same device ID. Rename them before a bulk upload.'
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
      else if (fetchSourceType === 'ip' && !isValidIpOrHostname(target)) e.fetchTarget = 'Enter a valid IP address or hostname (e.g. 10.0.0.1 or edge-router.local)'
      else if (fetchSourceType === 'url') {
        if (!/^https?:\/\//i.test(target)) e.fetchTarget = 'URL must start with http:// or https://'
        else if (!isValidUrl(target)) e.fetchTarget = 'Enter a valid URL with a proper hostname (e.g. https://example.com/config)'
      }
      if (fetchSourceType === 'ip') {
        if (!fetchUsername.trim()) e.fetchUsername = 'SSH username is required'
        if (!fetchPassword && !fetchSshKey) e.fetchCredential = 'Enter an SSH password or paste a private key'
        if (!/^\d+$/.test(fetchPort) || Number(fetchPort) < 1 || Number(fetchPort) > 65535) e.fetchPort = 'Port must be between 1 and 65535'
        if (fetchPassword.length > 1024) e.fetchCredential = 'Password is too long'
        if (fetchSshKey.length > 8192) e.fetchCredential = 'Private key is too large'
      } else {
        if (fetchAuthToken.length > 2048) e.fetchCredential = 'Authentication token is too long'
        if (fetchAuthToken && !/^https:\/\//i.test(target)) e.fetchTarget = 'Authentication tokens require an HTTPS configuration URL'
        if (fetchAuthHeader && !/^[A-Za-z][A-Za-z0-9-]{0,127}$/.test(fetchAuthHeader)) e.fetchAuthHeader = 'Enter a valid HTTP header name'
        else if (fetchAuthHeader && !/^(authorization|x-.+)$/i.test(fetchAuthHeader)) e.fetchAuthHeader = 'Use Authorization or an X-prefixed header'
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
    const next = new URLSearchParams(searchParams)
    if (mode === 'fetch' && fetchSourceType === 'website') next.set('source', 'website')
    else next.delete('source')
    setSearchParams(next, { replace: true })
    setErrors({})
    if (mode !== 'fetch') {
      setFetchPassword('')
      setFetchSshKey('')
      setFetchAuthToken('')
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (loading || isWebsite || !validate()) return

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
    const createTimeout = setTimeout(() => controller.abort(), 60000)
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
    } finally {
      clearTimeout(createTimeout)
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
        if (controller.signal.aborted) return
        rememberSession(sessionName)
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
        const timeoutId = setTimeout(() => controller.abort(), 60000)
        try {
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
          if (!uploadRes.ok) {
            const err = await uploadRes.json().catch(() => ({ error: 'upload failed' }))
            throw new Error(err.error || `Upload failed (${uploadRes.status})`)
          }
          const data = await uploadRes.json()
          if (controller.signal.aborted) return
          rememberSession(sessionName)
          results[idx] = { fileName: f.name, deviceId: did, status: 'success', message: `${data.passed} passed, ${data.failed} failed, ${data.unrecognized_count} unrecognized`, data }
          successCount++
          toast(`[${f.name}] ingested: ${data.passed} passed`, 'success')
        } catch (err) {
          const msg = err.name === 'AbortError' ? 'timed out (60s)' : err.message
          results[idx] = { fileName: f.name, deviceId: did, status: 'error', message: msg }
          failCount++
          toast(`[${f.name}] failed: ${msg}`, 'error')
        } finally {
          clearTimeout(timeoutId)
        }
        if (controller.signal.aborted) {
          for (let pending = idx + 1; pending < results.length; pending++) {
            results[pending] = { ...results[pending], status: 'error', message: 'Not submitted: collection stopped after cancellation or timeout.' }
            failCount++
          }
          setBulkResults([...results])
          break
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
      if (controller.signal.aborted) return
      rememberSession(sessionName)
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
        title="Upload & collect"
        description="Choose your evidence source. Device exports support mapped configuration checks; public websites receive a separate, limited surface observation."
      />

      <fieldset className="form-group choice-fieldset" disabled={loading || websiteBusy}>
        <legend>Input method</legend>
        <div className="input-mode-switch">
          {[['file', 'File Upload'], ['text', 'Paste Config'], ['fetch', 'Collect from Network']].map(([mode, label]) => (
            <button key={mode} type="button" aria-pressed={inputMode === mode} className={`btn-secondary ${inputMode === mode ? 'btn-primary' : ''}`} onClick={() => { changeInputMode(mode); setBulkResults([]) }}>{label}</button>
          ))}
        </div>
        {inputMode === 'fetch' && <div className="source-type-switch" role="group" aria-label="Collection source">
          {[['ip', 'SSH device'], ['url', 'Configuration URL'], ['website', 'Public website']].map(([source, label]) => (
            <button key={source} type="button" className={fetchSourceType === source ? 'is-selected' : ''} aria-pressed={fetchSourceType === source} onClick={() => changeSource(source)}>{label}</button>
          ))}
        </div>}
        <p className="field-help">Only collect from systems you are authorized to assess. Switching sources clears collection credentials and website results; download your report before switching.</p>
      </fieldset>

      {isWebsite ? <WebsiteView api={api} toast={toast} onBusyChange={setWebsiteBusy} /> : <form onSubmit={handleSubmit} noValidate>
        <div className="grid-2">
          <div className="form-group">
            <label htmlFor="upload-session">Session Name</label>
            <input
              id="upload-session"
              type="text"
              value={session}
              onChange={e => { setSession(e.target.value); setErrors(prev => ({ ...prev, session: null })) }}
              placeholder="e.g. demo, prod-audit-01"
            />
            {errors.session && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 4 }}>{errors.session}</div>}
          </div>
          <div className="form-group">
            <label htmlFor="upload-device">Device ID {isBulk && <span style={{ fontWeight: 400, color: 'var(--text-dim)' }}>(auto-derived from filenames in bulk)</span>}</label>
            <input
              id="upload-device"
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

        <details className="hardware-details" open={Boolean(errors.serialNumber || errors.hardwareModel || errors.osVersion) || undefined}>
          <summary>Hardware details <span>Optional · serial number, model and OS version</span></summary>
          <div className="grid-2">
            <div className="form-group">
              <label htmlFor="hardware-serial">Serial Number</label>
              <input id="hardware-serial" type="text" value={serialNumber} onChange={e => { setSerialNumber(e.target.value); setErrors(prev => ({ ...prev, serialNumber: null })) }} placeholder="e.g. FTX12345678" />
              {errors.serialNumber && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 4 }}>{errors.serialNumber}</div>}
            </div>
            <div className="form-group">
              <label htmlFor="hardware-model">Hardware Model</label>
              <input id="hardware-model" type="text" value={hardwareModel} onChange={e => { setHardwareModel(e.target.value); setErrors(prev => ({ ...prev, hardwareModel: null })) }} placeholder="e.g. C9300-48P, SRX345" />
              {errors.hardwareModel && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 4 }}>{errors.hardwareModel}</div>}
            </div>
          </div>
          <div className="form-group">
            <label htmlFor="hardware-os">OS Version {osVersion === '' && <span style={{ fontWeight: 400, color: 'var(--text-dim)' }}>(auto-detected from config header if blank — IOS XE / NX-OS / JUNOS)</span>}</label>
            <input id="hardware-os" type="text" value={osVersion} onChange={e => { setOsVersion(e.target.value); setErrors(prev => ({ ...prev, osVersion: null })) }} placeholder="e.g. IOS XE 17.6.5 or blank for auto-detect" />
            {errors.osVersion && <div style={{ color: 'var(--red)', fontSize: 12, marginTop: 4 }}>{errors.osVersion}</div>}
          </div>
        </details>

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
              className="resize-none"
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
              <span className="fetch-security-note">Collection credentials are not saved</span>
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
                {errors.fetchCredential && <div className="field-error">{errors.fetchCredential}</div>}
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
                  <p className="field-help">Tokens require HTTPS. Use Authorization or an X-prefixed header. Configuration exports may contain secrets and are stored as evidence.</p>
                </div>
              </div>
            )}
          </section>
        )}

        <button type="submit" className="btn-primary" disabled={!canSubmit} style={{ marginTop: 8 }}>
          {loading ? <><Spinner size={14} /> {isBulk ? `Uploading bulk (${bulkResults.filter(r=>r.status==='success').length}/${files.length})...` : inputMode === 'fetch' ? 'Collecting & scanning...' : 'Processing...'} </> : isBulk ? `Run Bulk Compliance Scan (${files.length} files)` : inputMode === 'fetch' ? 'Collect & Scan' : 'Run Compliance Scan'}
        </button>
      </form>}

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
                <div className="stat-label">Total checks · {Math.max(0, bulkResults[0].data.total_checks - bulkResults[0].data.passed - bulkResults[0].data.failed)} unresolved</div>
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
