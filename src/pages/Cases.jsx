import React, { useEffect, useState, useMemo } from 'react'
import { collection, onSnapshot, query, orderBy } from 'firebase/firestore'
import { db } from '../firebase'
import { useAuth } from '../AuthContext'
import { useNavigate, Link } from 'react-router-dom'

function caseToIncId(idx) {
  return 'INC-' + String(8800 + idx + 1).padStart(4, '0')
}

function getSevBadgeClass(sev) {
  const map = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' }
  return map[sev] || 'badge-neutral'
}

function getSevDotClass(sev) {
  const map = { critical: 'sev-dot-critical', high: 'sev-dot-high', medium: 'sev-dot-medium', low: 'sev-dot-low' }
  return map[sev] || ''
}

function getPriority(sev) {
  const map = { critical: 'P1', high: 'P1', medium: 'P2', low: 'P3' }
  return map[sev] || 'P3'
}

function getStatusBadgeClass(status) {
  switch (status) {
    case 'open': return 'badge-high'
    case 'investigating': return 'badge-medium'
    case 'contained': return 'badge-status'
    case 'closed': return 'badge-low'
    default: return 'badge-neutral'
  }
}

function formatDate(ts) {
  if (!ts) return '—'
  const d = ts.toDate ? ts.toDate() : new Date(ts)
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export default function Cases() {
  const { isAnalyst, canEdit } = useAuth()
  const navigate = useNavigate()
  const [cases, setCases] = useState([])
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  useEffect(() => {
    const q = query(collection(db, 'cases'), orderBy('created_at', 'desc'))
    const unsub = onSnapshot(q, snap => {
      setCases(snap.docs.map(d => ({ id: d.id, ...d.data() })))
    })
    return unsub
  }, [])

  const filtered = useMemo(() => {
    return cases.filter(c => {
      if (sevFilter && c.severity !== sevFilter) return false
      if (statusFilter && c.status !== statusFilter) return false
      if (search) {
        const s = search.toLowerCase()
        const inTitle = (c.title || '').toLowerCase().includes(s)
        const inAnalyst = (c.analyst || '').toLowerCase().includes(s)
        const inTags = (c.tags || []).join(' ').toLowerCase().includes(s)
        if (!inTitle && !inAnalyst && !inTags) return false
      }
      return true
    })
  }, [cases, search, sevFilter, statusFilter])

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Incident Queue</div>
          <div className="page-subtitle">{filtered.length} incidents{sevFilter || statusFilter ? ' (filtered)' : ''}</div>
        </div>
        <div className="page-actions">
          {canEdit && (
            <Link to="/cases/new" className="btn-primary" style={{ textDecoration: 'none' }}>
              + New Case
            </Link>
          )}
        </div>
      </div>

      {/* Filter Bar */}
      <div className="filter-bar">
        <input
          type="text"
          placeholder="Search cases..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ width: 240 }}
        />
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
        <select
          className="select-inline"
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          style={{ width: 'auto' }}
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="contained">Contained</option>
          <option value="closed">Closed</option>
        </select>
        {(sevFilter || statusFilter || search) && (
          <button
            className="btn-secondary"
            style={{ padding: '4px 10px', fontSize: 11 }}
            onClick={() => { setSevFilter(''); setStatusFilter(''); setSearch('') }}
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="table-section">
        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                {isAnalyst && <th style={{ width: 32 }}></th>}
                <th>Case ID</th>
                <th>Severity</th>
                <th>Title</th>
                <th>Assigned To</th>
                <th>Tactic</th>
                <th>Status</th>
                <th>Opened</th>
                {isAnalyst && <th style={{ width: 40 }}></th>}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={isAnalyst ? 9 : 7}>
                    <div className="empty-state">
                      <span className="empty-state-icon">◈</span>
                      <span className="empty-state-text">No incidents found</span>
                    </div>
                  </td>
                </tr>
              ) : (
                filtered.map((c, idx) => (
                  <tr key={c.id} onClick={() => navigate(`/cases/${c.id}`)}>
                    {canEdit && (
                      <td onClick={e => e.stopPropagation()}>
                        <input type="checkbox" style={{ width: 'auto' }} />
                      </td>
                    )}
                    <td className="td-id">{caseToIncId(idx)}</td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center' }}>
                        <span className={`sev-dot ${getSevDotClass(c.severity)}`}></span>
                        <span className={`badge ${getSevBadgeClass(c.severity)}`}>{getPriority(c.severity)}</span>
                      </span>
                    </td>
                    <td style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      <span style={{ fontWeight: 500 }}>{c.title || '—'}</span>
                    </td>
                    <td>
                      {c.analyst ? (
                        <div className="assigned-cell">
                          <div className="avatar-xs">{c.analyst.slice(0, 2).toUpperCase()}</div>
                          <span style={{ color: 'var(--text-secondary)' }}>{c.analyst}</span>
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>Not-Assigned</span>
                      )}
                    </td>
                    <td>
                      {c.mitre_tactics?.[0]
                        ? <span className="mitre-pill">{c.mitre_tactics[0]}</span>
                        : <span style={{ color: 'var(--text-muted)' }}>—</span>
                      }
                    </td>
                    <td>
                      <span className={`badge ${getStatusBadgeClass(c.status)}`}>{c.status || 'open'}</span>
                    </td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}>
                      {formatDate(c.created_at)}
                    </td>
                    {isAnalyst && (
                      <td className="row-actions" onClick={e => e.stopPropagation()}>
                        <button className="btn-icon" title="Actions">···</button>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
