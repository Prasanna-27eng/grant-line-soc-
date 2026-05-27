import React, { useEffect, useState, useMemo } from 'react'
import { collection, onSnapshot, query, where, orderBy } from 'firebase/firestore'
import { db } from '../firebase'
import { useNavigate } from 'react-router-dom'

function getSevBadgeClass(sev) {
  const map = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' }
  return map[sev] || 'badge-neutral'
}

function getDotClass(sev) {
  if (sev === 'critical') return 'timeline-dot timeline-dot-critical'
  if (sev === 'high') return 'timeline-dot timeline-dot-high'
  return 'timeline-dot'
}

function formatDateFull(ts) {
  if (!ts) return '—'
  const d = ts.toDate ? ts.toDate() : new Date(ts)
  return d.toLocaleString('en-US', {
    weekday: 'short', month: 'short', day: 'numeric',
    year: 'numeric', hour: '2-digit', minute: '2-digit'
  })
}

function formatDateShort(ts) {
  if (!ts) return '—'
  const d = ts.toDate ? ts.toDate() : new Date(ts)
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

export default function Timeline() {
  const navigate = useNavigate()
  const [cases, setCases] = useState([])
  const [selectedCase, setSelectedCase] = useState('')
  const [findings, setFindings] = useState([])

  useEffect(() => {
    const unsub = onSnapshot(
      query(collection(db, 'cases'), orderBy('created_at', 'desc')),
      snap => {
        const list = snap.docs.map(d => ({ id: d.id, ...d.data() }))
        setCases(list)
        if (!selectedCase && list.length > 0) {
          setSelectedCase(list[0].id)
        }
      }
    )
    return unsub
  }, [])

  useEffect(() => {
    if (!selectedCase) { setFindings([]); return }
    const q = query(
      collection(db, 'findings'),
      where('case_id', '==', selectedCase),
      orderBy('timestamp', 'asc')
    )
    const unsub = onSnapshot(q, snap => {
      setFindings(snap.docs.map(d => ({ id: d.id, ...d.data() })))
    })
    return unsub
  }, [selectedCase])

  const caseData = cases.find(c => c.id === selectedCase)

  // Group findings by date
  const grouped = useMemo(() => {
    const groups = []
    let currentDate = null
    findings.forEach(f => {
      const ts = f.timestamp?.toDate ? f.timestamp.toDate() : new Date(f.timestamp)
      const dateStr = ts.toDateString()
      if (dateStr !== currentDate) {
        currentDate = dateStr
        groups.push({ type: 'date', label: ts.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' }) })
      }
      groups.push({ type: 'finding', data: f })
    })
    return groups
  }, [findings])

  // Also add case creation event
  const allEvents = useMemo(() => {
    if (!caseData) return grouped
    const caseEvent = {
      type: 'case-created',
      ts: caseData.created_at,
    }
    return [caseEvent, ...grouped]
  }, [grouped, caseData])

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Attack Timeline</div>
          <div className="page-subtitle">Chronological view of case events and findings</div>
        </div>
        <div className="page-actions">
          <select
            value={selectedCase}
            onChange={e => setSelectedCase(e.target.value)}
            style={{ width: 'auto', minWidth: 300, background: 'var(--bg-elevated)', color: 'var(--text-primary)', border: '1px solid var(--border)', borderRadius: 6, padding: '7px 12px', fontSize: 13 }}
          >
            <option value="">Select a case...</option>
            {cases.map((c, idx) => (
              <option key={c.id} value={c.id}>
                INC-{c.id.slice(-4).toUpperCase()} — {c.title?.slice(0, 50) || 'Untitled'}
              </option>
            ))}
          </select>
        </div>
      </div>

      {!selectedCase ? (
        <div className="empty-state">
          <span className="empty-state-icon">◷</span>
          <span className="empty-state-text">Select a case to view its timeline</span>
        </div>
      ) : (
        <div>
          {/* Case Summary Bar */}
          {caseData && (
            <div className="card" style={{ marginBottom: 24, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
              <span
                style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: 'var(--accent)', cursor: 'pointer' }}
                onClick={() => navigate(`/cases/${selectedCase}`)}
              >
                INC-{selectedCase.slice(-4).toUpperCase()}
              </span>
              <span style={{ fontWeight: 600 }}>{caseData.title}</span>
              <span className={`badge ${getSevBadgeClass(caseData.severity)}`}>{caseData.severity}</span>
              <span style={{ color: 'var(--text-muted)', fontSize: 11, marginLeft: 'auto' }}>
                {findings.length} event{findings.length !== 1 ? 's' : ''} on timeline
              </span>
            </div>
          )}

          {findings.length === 0 && (
            <div className="empty-state">
              <span className="empty-state-icon">◷</span>
              <span className="empty-state-text">No findings in this case yet</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                Add findings in the case detail view to populate the timeline
              </span>
            </div>
          )}

          {findings.length > 0 && (
            <div className="timeline-container">
              <div className="timeline-line" />

              {/* Case opened event */}
              {caseData && (
                <div className="timeline-item">
                  <div className={`timeline-dot ${getDotClass(caseData.severity)}`} />
                  <div className="timeline-date">
                    {formatDateFull(caseData.created_at)}
                  </div>
                  <div className="timeline-card" style={{ borderColor: 'var(--accent-border)', background: 'rgba(56,189,248,0.06)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                      <span style={{ fontSize: 12, color: 'var(--accent)', fontWeight: 600 }}>⚑ Case Opened</span>
                      <span className={`badge ${getSevBadgeClass(caseData.severity)}`}>{caseData.severity}</span>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                      {caseData.description?.slice(0, 140) || 'Incident logged'}
                      {caseData.description?.length > 140 ? '...' : ''}
                    </div>
                    {caseData.analyst && (
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 6 }}>
                        Analyst: {caseData.analyst}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Finding events */}
              {findings.map(f => {
                const ts = f.timestamp?.toDate ? f.timestamp.toDate() : (f.timestamp ? new Date(f.timestamp) : null)
                return (
                  <div key={f.id} className="timeline-item">
                    <div className={getDotClass(f.severity)} />
                    <div className="timeline-date">
                      {ts ? ts.toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'}
                    </div>
                    <div className="timeline-card">
                      <div className="finding-header" style={{ marginBottom: 6 }}>
                        <span className="finding-title">{f.title}</span>
                        <span className={`badge ${getSevBadgeClass(f.severity)}`}>{f.severity}</span>
                        {f.mitre_technique && (
                          <span className="mitre-pill">{f.mitre_technique}</span>
                        )}
                      </div>
                      {f.description && (
                        <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                          {f.description}
                        </div>
                      )}
                      {f.evidence && (
                        <div className="finding-evidence" style={{ marginTop: 8, maxHeight: 80, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {f.evidence.slice(0, 200)}{f.evidence.length > 200 ? '...' : ''}
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}

              {/* Case status dot at end */}
              {caseData && (caseData.status === 'closed' || caseData.status === 'contained') && (
                <div className="timeline-item">
                  <div className="timeline-dot" style={{ background: 'var(--sev-low)', boxShadow: '0 0 8px rgba(63,185,80,0.5)' }} />
                  <div className="timeline-date">
                    {formatDateFull(caseData.updated_at)}
                  </div>
                  <div className="timeline-card" style={{ borderColor: 'rgba(63,185,80,0.3)', background: 'rgba(63,185,80,0.06)' }}>
                    <div style={{ fontSize: 12, color: 'var(--sev-low)', fontWeight: 600 }}>
                      ✓ Case {caseData.status === 'closed' ? 'Closed' : 'Contained'}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
