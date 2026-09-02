import { useState, useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import Spinner from '../components/Spinner'
import SceneHeader from '../components/SceneHeader'

const FRAMEWORKS = ['CIS', 'ISO27001', 'NIST_800-53', 'STIG', 'PCI-DSS', 'SOC2']
const PS_REQUIRED = new Set(['CIS', 'ISO27001', 'NIST_800-53', 'STIG'])

export default function ResultsView({ api, toast }) {
  const [params] = useSearchParams()
  const sessionParam = params.get('session') || ''
  const [session, setSession] = useState(sessionParam)
  const [inputSession, setInputSession] = useState(sessionParam)
  const [loading, setLoading] = useState(false)
  const [score, setScore] = useState(null)
  const [, setReport] = useState(null)
  const [activeFramework, setActiveFramework] = useState(null)
  const [error, setError] = useState(null)
  const [selectedFrameworks, setSelectedFrameworks] = useState(new Set(FRAMEWORKS))
  const abortRef = useRef(null)

  const toggleFramework = (fw) => {
    setSelectedFrameworks(prev => {
      const next = new Set(prev)
      if (next.has(fw)) {
        if (next.size === 1) return prev // keep at least one
        next.delete(fw)
      } else {
        next.add(fw)
      }
      return next
    })
  }
  const frameworksQuery = () => {
    if (selectedFrameworks.size === FRAMEWORKS.length) return ''
    return `?frameworks=${Array.from(selectedFrameworks).join(',')}`
  }

  useEffect(() => {
    if (sessionParam && sessionParam !== session) {
      setSession(sessionParam)
      setInputSession(sessionParam)
    }
  }, [sessionParam, session])

  const load = async (e) => {
    e?.preventDefault()
    const s = inputSession.trim()
    if (!s) return
    setLoading(true)
    setScore(null)
    setReport(null)
    setError(null)

    const controller = new AbortController()
    abortRef.current = controller
    const timeoutId = setTimeout(() => controller.abort(), 60000)

    try {
      const fq = frameworksQuery()
      const [scoreRes, reportRes] = await Promise.all([
        fetch(`${api}/session/${encodeURIComponent(s)}/score${fq}`, { signal: controller.signal }),
        fetch(`${api}/session/${encodeURIComponent(s)}/audit-report${fq}`, { signal: controller.signal }),
      ])
      clearTimeout(timeoutId)

      if (!scoreRes.ok) {
        const body = await scoreRes.json().catch(() => ({}))
        throw new Error(body.error || `Score request failed (${scoreRes.status})`)
      }
      if (!reportRes.ok) {
        const body = await reportRes.json().catch(() => ({}))
        throw new Error(body.error || `Report request failed (${reportRes.status})`)
      }

      const scoreData = await scoreRes.json()
      const reportData = await reportRes.json()
      setScore(scoreData.score || scoreData)
      setReport(reportData)
      setSession(s)
      if (scoreData.score?.frameworks) {
        const fws = Object.keys(scoreData.score.frameworks)
        setActiveFramework(fws[0] || null)
      }
      toast('Results loaded', 'success')
    } catch (err) {
      if (err.name === 'AbortError') {
        toast('Request timed out. Is the bridge running?', 'error')
        setError('Request timed out')
      } else {
        toast(err.message, 'error')
        setError(err.message)
      }
    } finally {
      clearTimeout(timeoutId)
      abortRef.current = null
      setLoading(false)
    }
  }

  const fwScore = score?.frameworks?.[activeFramework]

  return (
    <div>
      <SceneHeader
        index="02"
        label="Evaluate"
        title="Results & Score"
        description="View compliance scores per framework and detailed test results."
      />

      <section className="benchmark-panel" aria-labelledby="benchmark-heading">
        <div className="benchmark-heading-row">
          <div>
            <span className="benchmark-eyebrow">Scan scope</span>
            <h2 id="benchmark-heading">Benchmarks to evaluate</h2>
          </div>
          <span className="benchmark-count">{selectedFrameworks.size} / {FRAMEWORKS.length} selected</span>
        </div>
        <div className="benchmark-grid">
          {FRAMEWORKS.map(fw => (
            <label className={`benchmark-option${selectedFrameworks.has(fw) ? ' is-selected' : ''}`} key={fw}>
              <input type="checkbox" checked={selectedFrameworks.has(fw)} onChange={() => toggleFramework(fw)} />
              <span className="choice-control" aria-hidden="true" />
              <span className="benchmark-name">{fw.replace(/_/g, ' ')}</span>
              <span className="benchmark-tier">{PS_REQUIRED.has(fw) ? 'Core' : 'Extended'}</span>
            </label>
          ))}
        </div>
        <p className="benchmark-help">At least one benchmark remains active. Your selection filters scoring, reports, and PDF exports.</p>
      </section>

      <form onSubmit={load} noValidate style={{ display: 'flex', gap: 8, marginBottom: 24 }}>
        <input
          type="text"
          value={inputSession}
          onChange={e => setInputSession(e.target.value)}
          placeholder="Session name"
          style={{ flex: 1, maxWidth: 300 }}
        />
        <button type="submit" className="btn-primary" disabled={loading || !inputSession.trim()}>
          {loading ? <><Spinner size={14} /> Loading...</> : 'Load Results'}
        </button>
      </form>

      {!score && !loading && !error && (
        <div className="empty-state card">
          <h3>No results loaded</h3>
          <p>Enter a session name above to view compliance results.</p>
        </div>
      )}

      {error && !loading && (
        <div className="card">
          <h3 style={{ color: 'var(--red)', fontSize: 16, marginBottom: 4 }}>Failed to load results</h3>
          <p style={{ color: 'var(--text-dim)', fontSize: 13 }}>{error}</p>
          <button className="btn-secondary" onClick={load} style={{ marginTop: 8 }}>Retry</button>
        </div>
      )}

      {score && (
        <>
          {/* Overall score summary */}
          <div className="stat-grid">
            <div className="stat-card">
              <div className="stat-value">{score.total_tests_executed ?? 0}</div>
              <div className="stat-label">Tests Executed</div>
            </div>
            {Object.entries(score.frameworks || {}).map(([fw, data]) => (
              <div className="stat-card" key={fw}>
                <div className="stat-value">
                  {/* canonical scorer field is compliance_percentage (TrinetraComplianceScorer.java:132, bridge /score passthrough) */}
                  {data.compliance_percentage ?? '—'}%
                </div>
                <div className="stat-label">{fw.replace(/_/g, ' ')}</div>
              </div>
            ))}
          </div>

          {/* Framework tabs — all PS-required + bonus */}
          <div className="framework-tabs">
            {FRAMEWORKS.map(fw => (
              <button
                key={fw}
                type="button"
                className={`framework-tab ${activeFramework === fw ? 'active' : ''}`}
                onClick={() => setActiveFramework(fw)}
              >
                {fw.replace(/_/g, ' ')}
              </button>
            ))}
          </div>

          {/* Active framework detail */}
          {activeFramework && fwScore && (
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                  <h2 style={{ fontSize: 18, fontWeight: 600 }}>
                    {activeFramework.replace(/_/g, ' ')} Results
                  </h2>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <span style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--mono)' }}>
                      {/* canonical: compliance_percentage; fallback removed — API stable since STIG 14/15 (28 Aug) */}
                      {fwScore.compliance_percentage ?? 0}%
                    </span>
                    {!PS_REQUIRED.has(activeFramework) && (
                      <span className="badge badge-bonus">Bonus Coverage</span>
                    )}
                    {activeFramework === 'STIG' && fwScore.compliance_percentage != null && (
                      <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                        STIG coverage: {fwScore.tests_passed}/{fwScore.total_tests_mapped} controls mapped
                      </span>
                    )}
                  </div>
              </div>

              {/* Progress bar */}
              <div className="progress">
                <div
                  className="progress-bar"
                  style={{
                    width: `${fwScore.compliance_percentage ?? 0}%`,
                    background: (fwScore.compliance_percentage ?? 0) >= 80 ? 'var(--green)' :
                      (fwScore.compliance_percentage ?? 0) >= 50 ? 'var(--yellow)' : 'var(--red)',
                  }}
                />
              </div>

              {/* Tests table */}
              {fwScore.results && fwScore.results.length > 0 ? (
                <div className="table-wrap" style={{ marginTop: 16 }}>
                  <table>
                    <thead>
                      <tr>
                        <th>V-Code</th>
                        <th>Result</th>
                        <th>Remediation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {fwScore.results.map((r, i) => (
                        <tr key={i}>
                          <td style={{ fontFamily: 'var(--mono)', fontWeight: 600 }}>{r.test_id || r.vcode || r.id}</td>
                          <td>
                            <span className={`badge badge-${(r.result || r.status || '').toLowerCase() === 'pass' ? 'pass' : (r.result || r.status || '').toLowerCase() === 'fail' ? 'fail' : 'review'}`}>
                              {r.result || r.status || 'N/A'}
                            </span>
                          </td>
                          <td>
                            {r.remediation ? (
                              <div className={`remediation ${(r.remediation || '').toLowerCase().includes('ai-suggested') ? 'ai-suggested' : ''}`}>
                                {r.remediation}
                              </div>
                            ) : (
                              <span style={{ color: 'var(--text-dim)', fontSize: 12 }}>No remediation</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p style={{ color: 'var(--text-dim)', marginTop: 12, fontSize: 13 }}>
                  No per-test breakdown available for this framework.
                </p>
              )}
            </div>
          )}

          {/* PDF download — respects framework filter */}
          <div style={{ marginTop: 24 }}>
            <a
              href={`${api}/session/${encodeURIComponent(session)}/audit-report/pdf${frameworksQuery()}`}
              className="btn-primary"
              style={{ display: 'inline-block' }}
              target="_blank"
              rel="noopener noreferrer"
            >
              Download PDF Report {selectedFrameworks.size !== FRAMEWORKS.length ? `(${Array.from(selectedFrameworks).join(', ')})` : ''}
            </a>
          </div>
        </>
      )}
    </div>
  )
}
