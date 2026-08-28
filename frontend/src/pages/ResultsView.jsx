import { useState, useEffect, useRef } from 'react'
import Spinner from '../components/Spinner'

const FRAMEWORKS = ['ISO27001', 'NIST_800-53', 'PCI-DSS', 'SOC2', 'CIS']
const STIG_SUPPORTED = false

export default function ResultsView({ api, toast }) {
  const params = new URLSearchParams(window.location.search)
  const [session, setSession] = useState(params.get('session') || '')
  const [inputSession, setInputSession] = useState(params.get('session') || '')
  const [loading, setLoading] = useState(false)
  const [score, setScore] = useState(null)
  const [report, setReport] = useState(null)
  const [activeFramework, setActiveFramework] = useState(null)
  const [error, setError] = useState(null)
  const abortRef = useRef(null)

  useEffect(() => {
    const s = params.get('session')
    if (s && s !== session) {
      setSession(s)
      setInputSession(s)
    }
  }, [params.get('session')])

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
      const [scoreRes, reportRes] = await Promise.all([
        fetch(`${api}/session/${s}/score`, { signal: controller.signal }),
        fetch(`${api}/session/${s}/audit-report`, { signal: controller.signal }),
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
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 8 }}>Results &amp; Score</h1>
      <p style={{ color: 'var(--text-dim)', marginBottom: 24, fontSize: 14 }}>
        View compliance scores per framework and detailed test results.
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
        <div className="card" style={{ borderLeft: '3px solid var(--red)' }}>
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
                  {data.total_percentage ?? data.percentage ?? '—'}%
                </div>
                <div className="stat-label">{fw.replace('_', ' ')}</div>
              </div>
            ))}
          </div>

          {/* STIG badge */}
          {!STIG_SUPPORTED && (
            <div className="card" style={{ marginBottom: 16, padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 12 }}>
              <span className="badge badge-info">STIG</span>
              <span style={{ fontSize: 13, color: 'var(--text-dim)' }}>
                STIG framework support coming soon — not yet available for scoring
              </span>
            </div>
          )}

          {/* Framework tabs */}
          <div className="framework-tabs">
            {FRAMEWORKS.map(fw => (
              <button
                key={fw}
                className={`framework-tab ${activeFramework === fw ? 'active' : ''}`}
                onClick={() => setActiveFramework(fw)}
              >
                {fw.replace('_', ' ')}
              </button>
            ))}
            {!STIG_SUPPORTED && (
              <span className="framework-tab coming-soon" title="STIG mappings not yet implemented">
                STIG
              </span>
            )}
          </div>

          {/* Active framework detail */}
          {activeFramework && fwScore && (
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <h2 style={{ fontSize: 18, fontWeight: 600 }}>
                  {activeFramework.replace('_', ' ')} Results
                </h2>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--mono)' }}>
                    {fwScore.total_percentage ?? fwScore.percentage ?? 0}%
                  </span>
                  {(activeFramework === 'PCI-DSS' || activeFramework === 'SOC2') && (
                    <span className="badge badge-bonus">Bonus Coverage</span>
                  )}
                </div>
              </div>

              {/* Progress bar */}
              <div className="progress">
                <div
                  className="progress-bar"
                  style={{
                    width: `${fwScore.total_percentage ?? fwScore.percentage ?? 0}%`,
                    background: (fwScore.total_percentage ?? 0) >= 80 ? 'var(--green)' :
                      (fwScore.total_percentage ?? 0) >= 50 ? 'var(--yellow)' : 'var(--red)',
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

          {/* PDF download */}
          <div style={{ marginTop: 24 }}>
            <a
              href={`${api}/session/${session}/audit-report/pdf`}
              className="btn-primary"
              style={{ display: 'inline-block' }}
              target="_blank"
              rel="noopener noreferrer"
            >
              Download PDF Report
            </a>
          </div>
        </>
      )}
    </div>
  )
}
