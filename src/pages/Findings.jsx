import React, { useEffect, useState, useMemo } from 'react'
import { collection, onSnapshot, query, orderBy, getDocs } from 'firebase/firestore'
import { db } from '../firebase'
import { useNavigate } from 'react-router-dom'

function getSevBadgeClass(sev) {
  const map = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' }
  return map[sev] || 'badge-neutral'
}

function formatDate(ts) {
  if (!ts) return '—'
  const d = ts.toDate ? ts.toDate() : new Date(ts)
  return d.toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export default function Findings() {
  const navigate = useNavigate()
  const [findings, setFindings] = useState([])
  const [cases, setCases] = useState({})
  const [sevFilter, setSevFilter] = useState('')
  const [mitreFilter, setMitreFilter] = useState('')
  const [expandEvidence, setExpandEvidence] = useState({})

  useEffect(() => {
    // Load all cases for lookup
    const unsub = onSnapshot(collection(db, 'cases'), snap => {
      const map = {}
      snap.docs.forEach(d => { map[d.id] = { id: d.id, ...d.data() } })
      setCases(map)
    })
    return unsub
  }, [])

  useEffect(() => {
    const q = query(collection(db, 'findings'), orderBy('timestamp', 'desc'))
    const unsub = onSnapshot(q, snap => {
      setFindings(snap.docs.map(d => ({ id: d.id, ...d.data() })))
    })
    return unsub
  }, [])

  const filtered = useMemo(() => {
    return findings.filter(f => {
      if (sevFilter && f.severity !== sevFilter) return false
      if (mitreFilter && !(f.mitre_technique || '').toLowerCase().includes(mitreFilter.toLowerCase())) return false
      return true
    })
  }, [findings, sevFilter, mitreFilter])

  // Group by case_id
  const grouped = useMemo(() => {
    const groups = {}
    filtered.forEach(f => {
      const cid = f.case_id || 'unknown'
      if (!groups[cid]) groups[cid] = []
      groups[cid].push(f)
    })
    return groups
  }, [filtered])

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Intelligence Archive</div>
          <div className="page-subtitle">{filtered.length} findings across {Object.keys(grouped).length} cases</div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="filter-bar">
        <select
          className="select-inline"
          value={sevFilter}
          onChange={e => setSevFilter(e.target.value)}
          style={{ width: 'auto' }}
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <input
          type="text"
          placeholder="Filter by MITRE technique..."
          value={mitreFilter}
          onChange={e => setMitreFilter(e.target.value)}
          style={{ width: 220 }}
        />
        {(sevFilter || mitreFilter) && (
          <button className="btn-secondary" style={{ padding: '4px 10px', fontSize: 11 }} onClick={() => { setSevFilter(''); setMitreFilter('') }}>
            Clear
          </button>
        )}
      </div>

      {Object.keys(grouped).length === 0 ? (
        <div className="empty-state">
          <span className="empty-state-icon">◉</span>
          <span className="empty-state-text">No findings in the archive</span>
        </div>
      ) : (
        Object.entries(grouped).map(([caseId, caseFindings]) => {
          const c = cases[caseId]
          return (
            <div key={caseId} className="table-section" style={{ marginBottom: 16 }}>
              <div className="table-section-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span
                    style={{
                      fontFamily: 'JetBrains Mono, monospace',
                      fontSize: 12,
                      color: 'var(--accent)',
                      cursor: 'pointer',
                    }}
                    onClick={() => navigate(`/cases/${caseId}`)}
                    title="Open case"
                  >
                    {c ? `INC-${caseId.slice(-4).toUpperCase()}` : caseId.slice(-8)}
                  </span>
                  {c && (
                    <span
                      style={{ fontWeight: 600, cursor: 'pointer' }}
                      onClick={() => navigate(`/cases/${caseId}`)}
                    >
                      {c.title}
                    </span>
                  )}
                  {c && (
                    <span className={`badge ${getSevBadgeClass(c.severity)}`}>{c.severity}</span>
                  )}
                </div>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  {caseFindings.length} finding{caseFindings.length !== 1 ? 's' : ''}
                </span>
              </div>

              {caseFindings.map(f => (
                <div key={f.id} className="finding-item">
                  <div className="finding-header">
                    <span className="finding-title">{f.title}</span>
                    <span className={`badge ${getSevBadgeClass(f.severity)}`}>{f.severity}</span>
                    {f.mitre_technique && (
                      <span className="mitre-pill">{f.mitre_technique}</span>
                    )}
                  </div>
                  {f.description && (
                    <div className="finding-body">{f.description}</div>
                  )}
                  {f.evidence && (
                    <div>
                      <button
                        className="btn-icon"
                        style={{ fontSize: 11, color: 'var(--text-muted)', padding: '2px 0' }}
                        onClick={() => setExpandEvidence(p => ({ ...p, [f.id]: !p[f.id] }))}
                      >
                        {expandEvidence[f.id] ? '▲ Hide evidence' : '▶ Show evidence'}
                      </button>
                      {expandEvidence[f.id] && (
                        <div className="finding-evidence">{f.evidence}</div>
                      )}
                    </div>
                  )}
                  <div className="finding-meta">
                    <span className="finding-ts">
                      {f.timestamp?.toDate
                        ? f.timestamp.toDate().toLocaleString()
                        : f.timestamp
                          ? new Date(f.timestamp).toLocaleString()
                          : '—'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )
        })
      )}
    </div>
  )
}
