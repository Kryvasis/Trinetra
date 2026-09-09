import { useState, useEffect, useRef } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import Spinner from '../components/Spinner'
import SceneHeader from '../components/SceneHeader'
import { rememberSession, validSession } from '../utils/activeSession'

export default function TrainingView({ api, toast }) {
  const [params] = useSearchParams()
  const sessionParam = params.get('session') || ''
  const [session, setSession] = useState(sessionParam)
  const [inputSession, setInputSession] = useState(sessionParam)
  const [loading, setLoading] = useState(false)
  const [unrecognized, setUnrecognized] = useState([])
  const [totalBefore, setTotalBefore] = useState(0)
  const [totalAfter, setTotalAfter] = useState(0)
  const [error, setError] = useState(null)
  const [hasLoaded, setHasLoaded] = useState(false)
  const fetchRef = useRef(null)
  const sessionInputRef = useRef(null)
  const patternRef = useRef(null)
  const categoryRef = useRef(null)
  const summaryRef = useRef(null)
  useEffect(() => { if (hasLoaded && totalAfter < totalBefore) summaryRef.current?.focus() }, [hasLoaded, totalAfter, totalBefore])

  // Training form state
  const [selectedLine, setSelectedLine] = useState(null)
  const [vendor, setVendor] = useState('Cisco')
  const [pattern, setPattern] = useState('')
  const [category, setCategory] = useState('')
  const [controlMapping, setControlMapping] = useState('')
  const [remediation, setRemediation] = useState('')
  const [osVersionTrain, setOsVersionTrain] = useState('')
  const [training, setTraining] = useState(false)
  const [trainErrors, setTrainErrors] = useState({})
  const [mlSuggestions, setMlSuggestions] = useState({}) // line -> {label, confidence, source}
  const [nlpSuggestions, setNlpSuggestions] = useState({}) // line -> {category, control, remediation, confidence, reasoning}
  const [mlStatus, setMlStatus] = useState(null)
  const abortRef = useRef(null)
  useEffect(() => () => { abortRef.current?.abort(); abortRef.current = null }, [])

  useEffect(() => {
    if (sessionParam && sessionParam !== session) {
      setSession(sessionParam)
      setInputSession(sessionParam)
    }
  }, [sessionParam, session])

  const fetchMlSuggestions = async (lines) => {
    if (!lines || lines.length === 0) { setMlSuggestions({}); setNlpSuggestions({}); return }
    // batch up to 20 lines for quick UI
    const slice = lines.slice(0, 20)
    try {
      const results = await Promise.all(slice.map(async item => {
        try {
          const r = await fetch(`${api}/ml/suggest`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ line: item.line, vendor }) })
          const j = await r.json()
          return [item.line, j.ml || null]
        } catch { return [item.line, null] }
      }))
      const map = {}
      for (const [k,v] of results) if (v) map[k]=v
      setMlSuggestions(map)
    } catch { setMlSuggestions({}) }
    // also fetch model status for footer
    try {
      const r = await fetch(`${api}/ml/status`)
      const j = await r.json()
      setMlStatus(j)
    } catch { setMlStatus(null) }
    // NLP Pattern Recognition + semantic interpretation (Gemini) — parallel, never overwrites KNN
    try {
      const nlpResults = await Promise.all(slice.slice(0,5).map(async item => {
        try {
          const r = await fetch(`${api}/nlp/suggest`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ line: item.line, vendor }) })
          const j = await r.json()
          return [item.line, j.nlp || null]
        } catch { return [item.line, null] }
      }))
      const nmap = {}
      for (const [k,v] of nlpResults) if (v) nmap[k]=v
      setNlpSuggestions(nmap)
    } catch { setNlpSuggestions({}) }
  }

  const fetchUnrecognized = async (sessName) => {
    if (training) return
    if (!validSession(sessName)) { setError('Use 1–64 letters, numbers, hyphens or underscores.'); sessionInputRef.current?.focus(); return }
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    const timeoutId = setTimeout(() => controller.abort(), 30000)
    setLoading(true)
    setError(null)
    setSelectedLine(null)
    setHasLoaded(false); setUnrecognized([]); setTotalBefore(0); setTotalAfter(0)
    try {

      const res = await fetch(`${api}/session/${encodeURIComponent(sessName)}/unrecognized`, { signal: controller.signal })
      clearTimeout(timeoutId)
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.error || `Failed to load: ${res.status}`)
      }
      const data = await res.json()
      if (controller.signal.aborted || abortRef.current !== controller) return
      setHasLoaded(true)
      rememberSession(sessName)
      const lines = []
      Object.entries(data.unrecognized_by_device || {}).forEach(([dev, devLines]) => {
        devLines.forEach(line => lines.push({ device: dev, line }))
      })
      setUnrecognized(lines)
      setTotalBefore(lines.length)
      setTotalAfter(lines.length)
      if (lines.length === 0) {
        toast('No unrecognized lines in this session', 'info')
      } else {
        toast(`Found ${lines.length} unrecognized line(s)`, 'info')
        // parallel ML advisory (TF-IDF + KNN) — never blocks, fills suggestion badges
        fetchMlSuggestions(lines)
      }
    } catch (err) {
      if (abortRef.current !== controller) return
      if (err.name === 'AbortError') {
        setError('Request timed out. Check the backend and retry.')
        toast('Request timed out. Is the bridge running?', 'error')
      } else {
        setError(err.message)
        toast(err.message, 'error')
      }
    } finally {
      clearTimeout(timeoutId)
      if (abortRef.current === controller) { abortRef.current = null; setLoading(false) }
    }
  }
  useEffect(() => { fetchRef.current = fetchUnrecognized })
  useEffect(() => { if (sessionParam) fetchRef.current(sessionParam) }, [sessionParam])

  const load = (e) => {
    e?.preventDefault()
    const s = inputSession.trim()
    if (!s) return
    setSession(s)
    fetchUnrecognized(s)
  }

  const validateTraining = () => {
    const e = {}
    if (!selectedLine) e.line = 'Select a line first'
    if (!pattern.trim()) e.pattern = 'Pattern is required'
    else {
      try { new RegExp(pattern.trim()) } catch { e.pattern = 'Invalid regex pattern' }
    }
    if (!category.trim()) e.category = 'Security category is required'
    else if (category.trim().length < 2) e.category = 'Category must be at least 2 characters'
    setTrainErrors(e)
    if (e.pattern) patternRef.current?.focus()
    else if (e.category) categoryRef.current?.focus()
    return Object.keys(e).length === 0
  }

  const handleTrain = async (e) => {
    e.preventDefault()
    if (training || loading) return
    if (!validateTraining()) return

    setTraining(true)
    setError(null)
    const controller = new AbortController()
    abortRef.current = controller
    const timeoutId = setTimeout(() => controller.abort(), 30000)

    try {
      const payload = {
        vendor: vendor.trim() || 'Cisco',
        pattern: pattern.trim(),
        security_category: category.trim(),
        control_mapping: controlMapping.split(',').map(s => s.trim()).filter(Boolean),
        remediation: remediation.trim() || `Configure ${category.trim()} properly`,
        os_version: osVersionTrain.trim() || undefined,
      }
      const res = await fetch(`${api}/session/${encodeURIComponent(session)}/train`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      })
      clearTimeout(timeoutId)
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'training failed' }))
        throw new Error(err.error || `Training failed: ${res.status}`)
      }
      if (abortRef.current !== controller) return
      toast('Training entry added — re-upload config to see effect', 'success')
      // Clear form
      setSelectedLine(null)
      setPattern('')
      setCategory('')
      setControlMapping('')
      setRemediation('')
      setOsVersionTrain('')
      setTrainErrors({})
      // Re-fetch to show updated count
      const newUnrecognized = unrecognized.filter(u => u.line !== selectedLine)
      setUnrecognized(newUnrecognized)
      setTotalAfter(newUnrecognized.length)
    } catch (err) {
      if (abortRef.current !== controller) return
      setError(err.name === 'AbortError' ? 'Training timed out and may have completed. Check saved patterns before retrying.' : err.message)
      if (err.name === 'AbortError') {
        toast('Training request timed out', 'error')
      } else {
        toast(err.message, 'error')
      }
    } finally {
      clearTimeout(timeoutId)
      if (abortRef.current === controller) { abortRef.current = null; setTraining(false) }
    }
  }

  const selectLine = (line) => {
    setSelectedLine(line)
    setPattern(line.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\.\*/g, '.*'))
    const nlp = nlpSuggestions[line]
    const ml = mlSuggestions[line]
    if (nlp && nlp.category) {
      setCategory(nlp.category)
      setControlMapping(nlp.control || '')
      setRemediation(nlp.remediation || '')
      toast(`NLP suggests: ${nlp.category} → ${nlp.control} (${Math.round(nlp.confidence*100)}% Gemini: ${nlp.reasoning?.slice(0,60)}…) — verify before adding`, 'info')
    } else if (ml && ml.label) {
      setCategory(ml.label)
      if (/^V-\d+/.test(ml.label)) {
        setControlMapping(ml.label)
        setCategory('ML-suggested: ' + ml.label)
      }
      toast(`AI suggests: ${ml.label} (${Math.round(ml.confidence*100)}% via ${ml.source}) — verify before adding`, 'info')
    } else {
      setCategory('')
      setControlMapping('')
    }
    if (!nlp) setRemediation('')
    setOsVersionTrain('')
    setTrainErrors({})
  }

  return (
    <div>
      <SceneHeader
        index="03"
        label="Learn"
        title="Training Loop"
        description="Label unrecognized config lines to teach Cortex new patterns — no code changes required."
      />

      <form onSubmit={load} noValidate className="assessment-toolbar">
        <label htmlFor="training-session">Saved session</label>
        <input
          id="training-session"
          ref={sessionInputRef} maxLength={64} aria-invalid={!!error && !validSession(inputSession.trim())} aria-describedby={error ? 'training-error' : undefined}
          disabled={loading || training}
          type="text"
          value={inputSession}
          onChange={e => setInputSession(e.target.value)}
          placeholder="Session name"
          style={{ flex: 1, maxWidth: 300 }}
        />
        <button type="submit" className="btn-primary" disabled={loading || training || !inputSession.trim()}>
          {loading ? <><Spinner size={14} /> Loading...</> : 'Load Unrecognized Lines'}
        </button>
      </form>

      {!session && !loading && <div className="empty-state card"><h2>Choose an assessment</h2><p>Open a saved session or upload a configuration to review unrecognized directives. Training records pattern mappings; it does not establish security compliance.</p><Link className="btn-secondary" to="/upload">Upload & collect</Link></div>}

      {loading && (
        <div className="empty-state card">
          <Spinner size={24} />
          <p style={{ marginTop: 12 }}>Loading unrecognized lines...</p>
        </div>
      )}

      {error && !loading && (
        <div className="card" role="alert" id="training-error">
          <h3 style={{ color: 'var(--red)', fontSize: 16, marginBottom: 4 }}>Training request unavailable</h3>
          <p style={{ color: 'var(--text-dim)', fontSize: 13 }}>{error}</p>
          <button className="btn-secondary" onClick={() => fetchUnrecognized(inputSession.trim())} style={{ marginTop: 8 }}>
            Retry
          </button>
        </div>
      )}

      {!loading && hasLoaded && unrecognized.length === 0 && !error && (
        <div className="empty-state card">
          <h3>{totalBefore > 0 ? 'Review complete' : 'No unrecognized lines'}</h3>
          <p>{totalBefore > 0 ? 'Every line in this review has a saved label. Re-upload the configuration to verify recognition.' : 'No unrecognized lines were returned. Pattern recognition is not proof that this configuration is secure.'}</p>
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
            {unrecognized.map((u, i) => {
              const ml = mlSuggestions[u.line]
              const nlp = nlpSuggestions[u.line]
              return (
              <button
                type="button"
                disabled={training}
                key={i}
                className="line-item"
                style={{
                  cursor: 'pointer',
                  background: selectedLine === u.line ? 'var(--surface2)' : 'transparent',
                  border: selectedLine === u.line ? '1px solid var(--accent)' : '1px solid var(--border)',
                }}
                onClick={() => selectLine(u.line)}
                aria-pressed={selectedLine === u.line}
              >
                <span style={{ fontSize: 11, color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>{u.device}</span>
                <span className="line-text">{u.line}</span>
                {ml && <span className="badge" style={{ marginLeft:8, background:'var(--surface3)', fontSize:10 }} title={`ML: ${ml.source} conf ${ml.confidence}`}>AI: {ml.label} {Math.round(ml.confidence*100)}%</span>}
                {nlp && <span className="badge" style={{ marginLeft:8, background:'var(--accent)', color:'#fff', fontSize:10 }} title={`NLP: ${nlp.reasoning}`}>NLP: {nlp.category} {Math.round(nlp.confidence*100)}%</span>}
              </button>
              )
            })}
          </div>

          {/* Right: training form */}
          <div className="card">
            <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>
              {selectedLine ? 'Label Selected Line' : 'Select a line to label'}
            </h2>
            {selectedLine && (
              <form onSubmit={handleTrain} noValidate>
                <div className="card" style={{ marginBottom: 16, padding: 12 }}>
                  <code style={{ fontSize: 12, wordBreak: 'break-all' }}>{selectedLine}</code>
                </div>

                <div className="form-group">
                  <label htmlFor="training-vendor">Vendor</label>
                  <select id="training-vendor" disabled={training} value={vendor} onChange={e => setVendor(e.target.value)}>
                    <option value="Cisco">Cisco</option>
                    <option value="Juniper">Juniper</option>
                    <option value="FortiOS">FortiOS</option>
                    <option value="PAN-OS">PAN-OS</option>
                    <option value="SONiC">SONiC</option>
                    <option value="AWS">AWS</option>
                    <option value="Generic">Generic</option>
                  </select>
                </div>

                <div className="form-group">
                  <label htmlFor="training-pattern">Regex Pattern (auto-generated, editable)</label>
                  <input
                    id="training-pattern" ref={patternRef} disabled={training} aria-invalid={!!trainErrors.pattern} aria-describedby={trainErrors.pattern ? 'training-pattern-error' : undefined}
                    type="text"
                    value={pattern}
                    onChange={e => { setPattern(e.target.value); setTrainErrors(prev => ({ ...prev, pattern: null })) }}
                    style={{ fontFamily: 'var(--mono)' }}
                  />
                  {trainErrors.pattern && <div id="training-pattern-error" style={{ color: 'var(--red)', fontSize: 12, marginTop: 4 }}>{trainErrors.pattern}</div>}
                </div>

                <div className="form-group">
                  <label htmlFor="training-category">Security Category</label>
                  <input
                    id="training-category" ref={categoryRef} disabled={training} aria-invalid={!!trainErrors.category} aria-describedby={trainErrors.category ? 'training-category-error' : undefined}
                    type="text"
                    value={category}
                    onChange={e => { setCategory(e.target.value); setTrainErrors(prev => ({ ...prev, category: null })) }}
                    placeholder="e.g. Access Control, Logging, Encryption"
                  />
                  {trainErrors.category && <div id="training-category-error" style={{ color: 'var(--red)', fontSize: 12, marginTop: 4 }}>{trainErrors.category}</div>}
                </div>

                <div className="form-group">
                  <label htmlFor="training-controls">Control Mapping (comma-separated)</label>
                  <input
                    id="training-controls" disabled={training}
                    type="text"
                    value={controlMapping}
                    onChange={e => setControlMapping(e.target.value)}
                    placeholder="e.g. CIS-v8-4.6, ISO27001-A.9"
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="training-remediation">Remediation (optional)</label>
                  <textarea
                    id="training-remediation" disabled={training}
                    className="resize-none"
                    value={remediation}
                    onChange={e => setRemediation(e.target.value)}
                    rows={3}
                    placeholder="How to remediate this finding..."
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="training-os">OS Version (optional)</label>
                  <input
                    id="training-os" disabled={training}
                    type="text"
                    value={osVersionTrain}
                    onChange={e => setOsVersionTrain(e.target.value)}
                    placeholder="e.g. IOS XE 17.6.5, NX-OS 9.3(9), JUNOS 20.4R3"
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
      {hasLoaded && totalBefore > 0 && (
        <div ref={summaryRef} tabIndex={-1} className="card" role="region" aria-label="Training review progress" style={{ marginTop: 16 }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24, alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Loaded for review
              </div>
              <div style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--mono)' }}>{totalBefore}</div>
            </div>
            <div style={{ fontSize: 24, color: 'var(--text-dim)' }}>→</div>
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                Remaining in this review
              </div>
              <div style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--mono)', color: totalAfter < totalBefore ? 'var(--green)' : 'inherit' }}>
                {totalAfter}
              </div>
            </div>
            {totalAfter < totalBefore && (
              <span className="badge badge-pass">{totalBefore - totalAfter} line(s) labeled in this review</span>
            )}
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 12 }}>
            Saved patterns take effect on the next configuration upload. These counts track this review only; re-upload the configuration to verify recognition. A saved label is not proof of security compliance.
          </p>
          {mlStatus && <p style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 8 }}>
            ML: {mlStatus.has_sklearn ? `TF-IDF char 3-5 + KNN(k=${mlStatus.k}, cosine) — corpus ${mlStatus.corpus_size}, model ${mlStatus.model_exists ? 'ready' : 'training'}` : 'sklearn not installed — regex only fallback'} · Threshold 0.55 · Deterministic scorer remains authoritative, ML is advisory
          </p>}
        </div>
      )}
    </div>
  )
}
