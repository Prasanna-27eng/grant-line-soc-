import React, { useEffect, useState, useMemo } from 'react'
import { collection, onSnapshot, query, orderBy } from 'firebase/firestore'
import { db } from '../firebase'
import { useAuth } from '../AuthContext'
import { useNavigate, Link } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from 'recharts'

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

const CATEGORIES = [
  'General', 'Malware', 'Phishing', 'C2', 'Data Exfil',
  'Ransomware', 'Insider Threat', 'Endpoints', 'Network', 'Identity', 'MITRE'
]

const SEV_PRIORITY = { critical: 'P1', high: 'P1', medium: 'P2', low: 'P2' }

function caseToIncId(idx) {
  return 'INC-' + String(8800 + idx + 1).padStart(4, '0')
}

function getSevClass(sev) {
  const map = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' }
  return map[sev] || 'badge-neutral'
}

function getSevDotClass(sev) {
  const map = { critical: 'sev-dot-critical', high: 'sev-dot-high', medium: 'sev-dot-medium', low: 'sev-dot-low' }
  return map[sev] || ''
}

function getPriority(sev) {
  return SEV_PRIORITY[sev] || 'P3'
}

function formatDate(ts) {
  if (!ts) return '—'
  const d = ts.toDate ? ts.toDate() : new Date(ts)
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function buildChartData(cases) {
  const now = new Date()
  const year = now.getFullYear()
  const data = MONTHS.map((m, i) => ({ month: m, P1: 0, P2: 0 }))
  cases.forEach(c => {
    const d = c.created_at?.toDate ? c.created_at.toDate() : null
    if (d && d.getFullYear() === year) {
      const mi = d.getMonth()
      const priority = getPriority(c.severity)
      if (priority === 'P1') data[mi].P1++
      else data[mi].P2++
    }
  })
  return data
}

function buildPulseData(cases) {
  const total = cases.length || 1
  const closed = cases.filter(c => c.status === 'closed' || c.status === 'contained').length
  const withMitre = cases.filter(c => c.mitre_tactics?.length > 0).length
  const investigating = cases.filter(c => c.status === 'investigating').length
  const covered = Math.round((closed / total) * 10)
  const detection = Math.min(10, Math.round((withMitre / total) * 10) + 3)
  const recovery = Math.min(10, Math.round((closed / total) * 8) + 2)
  const compliance = Math.min(10, 6 + Math.round((closed / total) * 4))
  const awareness = Math.min(10, 5 + Math.round((investigating / total) * 5))
  const resilience = Math.min(10, Math.round(((closed + investigating) / total) * 9) + 1)
  return [
    { label: 'Coverage', value: covered },
    { label: 'Detection', value: detection },
    { label: 'Recovery', value: recovery },
    { label: 'Compliance', value: compliance },
    { label: 'Awareness', value: awareness },
    { label: 'Resilience', value: resilience },
  ]
}

function PulseBar({ value }) {
  const segs = 10
  return (
    <div className="pulse-bar-track">
      {Array.from({ length: segs }, (_, i) => (
        <div
          key={i}
          className={`pulse-seg ${i < value ? (i < value * 0.7 ? 'filled' : 'filled-dim') : ''}`}
        />
      ))}
    </div>
  )
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: '#1c2333',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 6,
      padding: '8px 14px',
      fontSize: 12,
      color: '#e6edf3',
      fontFamily: 'JetBrains Mono, monospace'
    }}>
      <div style={{ marginBottom: 4, color: '#8b949e' }}>{label}</div>
      {payload.map(p => (
        <div key={p.dataKey} style={{ color: p.fill }}>
          {p.dataKey}: {p.value}
        </div>
      ))}
    </div>
  )
}

export default function Dashboard() {
  const { isAnalyst, canEdit, isGuest } = useAuth()
  const navigate = useNavigate()
  const [cases, setCases] = useState([])
  const [iocs, setIocs] = useState([])
  const [activeCategory, setActiveCategory] = useState('General')
  const [sevFilter, setSevFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  useEffect(() => {
    const q = query(collection(db, 'cases'), orderBy('created_at', 'desc'))
    const unsub = onSnapshot(q, snap => {
      setCases(snap.docs.map(d => ({ id: d.id, ...d.data() })))
    })
    return unsub
  }, [])

  useEffect(() => {
    const unsub = onSnapshot(collection(db, 'iocs'), snap => {
      setIocs(snap.docs.map(d => ({ id: d.id, ...d.data() })))
    })
    return unsub
  }, [])

  const chartData = useMemo(() => buildChartData(cases), [cases])
  const pulseData = useMemo(() => buildPulseData(cases), [cases])

  const openCases = cases.filter(c => c.status === 'open' || c.status === 'investigating')
  const closedCases = cases.filter(c => c.status === 'closed' || c.status === 'contained')
  const detectionRate = cases.length
    ? Math.round((closedCases.length / cases.length) * 100)
    : 0

  const filteredCases = useMemo(() => {
    return cases.filter(c => {
      if (sevFilter && c.severity !== sevFilter) return false
      if (statusFilter && c.status !== statusFilter) return false
      if (activeCategory !== 'General' && activeCategory !== 'MITRE') {
        const tactics = (c.mitre_tactics || []).join(' ').toLowerCase()
        const title = (c.title || '').toLowerCase()
        const cat = activeCategory.toLowerCase()
        if (!tactics.includes(cat) && !title.includes(cat) && !(c.tags || []).join(' ').toLowerCase().includes(cat)) {
          return false
        }
      }
      return true
    })
  }, [cases, sevFilter, statusFilter, activeCategory])

  return (
    <div>
      {/* Guest Banner */}
      {isGuest && (
        <div className="guest-banner">
          <span>👁 Viewing as guest — read-only mode</span>
          <Link to="/login">Sign in →</Link>
        </div>
      )}

      {/* Page Header */}
      <div className="page-header">
        <div>
          <div className="page-title">SOC Command Center ⊞</div>
          <div className="page-subtitle">
            Monitoring <strong style={{ color: 'var(--accent)' }}>{openCases.length}</strong> active threats across <strong style={{ color: 'var(--accent)' }}>{cases.length}</strong> cases
          </div>
        </div>
      </div>

      {/* Stat Row */}
      <div className="stat-row">
        <div className="stat-block">
          <div className="stat-label">⚡ Active Alerts</div>
          <div className="stat-number">{openCases.length}</div>
          <div className="stat-suffix">/ {cases.length} total</div>
        </div>
        <div className="stat-block">
          <div className="stat-label">🔗 IOC Sources</div>
          <div className="stat-number">{iocs.length}</div>
          <div className="stat-suffix">/ {new Set(iocs.map(i => i.type)).size} types</div>
        </div>
        <div className="stat-block">
          <div className="stat-label">📡 Detection Rate</div>
          <div className="stat-number">{detectionRate}<span style={{ fontSize: 18, color: 'var(--text-muted)' }}>%</span></div>
          <div className="stat-suffix">/ 7d window</div>
        </div>
      </div>

      {/* Category Tabs */}
      <div className="tab-bar">
        {CATEGORIES.map(cat => (
          <button
            key={cat}
            className={`tab-item ${activeCategory === cat ? 'active' : ''}`}
            onClick={() => setActiveCategory(cat)}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Charts Row */}
      <div className="dashboard-charts-row">
        {/* Threat Volume Chart */}
        <div className="chart-panel">
          <div className="chart-panel-header">
            <span className="chart-title">Threat Volume</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <div className="chart-legend">
                <span>
                  <span className="legend-dot" style={{ background: '#1e4976' }}></span>P1
                </span>
                <span>
                  <span className="legend-dot" style={{ background: '#38bdf8' }}></span>P2
                </span>
                <span>
                  <span className="legend-dot" style={{ background: '#f85149' }}></span>Critical
                </span>
              </div>
              <select className="select-inline">
                <option>One year ▾</option>
              </select>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={chartData} barGap={2} barSize={14}>
              <XAxis
                dataKey="month"
                tick={{ fill: '#484f58', fontSize: 11, fontFamily: 'Inter' }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: '#484f58', fontSize: 11, fontFamily: 'Inter' }}
                axisLine={false}
                tickLine={false}
                width={30}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
              <Bar dataKey="P1" stackId="a" fill="#1e4976" radius={[0, 0, 2, 2]} />
              <Bar dataKey="P2" stackId="a" fill="#38bdf8" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Security Pulse */}
        <div className="pulse-panel">
          <div className="pulse-panel-header">
            <span className="pulse-title">Security Pulse</span>
            <span className="pulse-link">Detail Info →</span>
          </div>
          <div className="pulse-rows">
            {pulseData.map(row => (
              <div key={row.label} className="pulse-row">
                <span className="pulse-label">{row.label}</span>
                <PulseBar value={row.value} />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Incident Queue */}
      <div className="table-section">
        <div className="table-section-header">
          <span className="table-section-title">Incident Queue</span>
          <div className="table-filter-row">
            {sevFilter && (
              <span className="filter-pill">
                Severity: {sevFilter}
                <span className="pill-remove" onClick={() => setSevFilter('')}> ×</span>
              </span>
            )}
            {statusFilter && (
              <span className="filter-pill">
                Status: {statusFilter}
                <span className="pill-remove" onClick={() => setStatusFilter('')}> ×</span>
              </span>
            )}
            <select
              className="select-inline"
              value={sevFilter}
              onChange={e => setSevFilter(e.target.value)}
            >
              <option value="">Severity ▾</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select
              className="select-inline"
              value={statusFilter}
              onChange={e => setStatusFilter(e.target.value)}
            >
              <option value="">Status ▾</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="contained">Contained</option>
              <option value="closed">Closed</option>
            </select>
          </div>
        </div>
        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                {canEdit && <th style={{ width: 32 }}></th>}
                <th>Case ID</th>
                <th>Severity</th>
                <th>Title / Host</th>
                <th>Assigned To</th>
                <th>Threat Type</th>
                <th>Status</th>
                <th>Time Opened</th>
                {canEdit && <th style={{ width: 40 }}></th>}
              </tr>
            </thead>
            <tbody>
              {filteredCases.length === 0 ? (
                <tr>
                  <td colSpan={canEdit ? 9 : 7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '40px' }}>
                    No incidents found
                  </td>
                </tr>
              ) : (
                filteredCases.map((c, idx) => (
                  <tr
                    key={c.id}
                    onClick={() => navigate(`/cases/${c.id}`)}
                    style={{ cursor: 'pointer' }}
                  >
                    {canEdit && (
                      <td onClick={e => e.stopPropagation()}>
                        <input type="checkbox" style={{ width: 'auto' }} />
                      </td>
                    )}
                    <td className="td-id">{caseToIncId(idx)}</td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center' }}>
                        <span className={`sev-dot ${getSevDotClass(c.severity)}`}></span>
                        <span className={`badge ${getSevClass(c.severity)}`}>{getPriority(c.severity)}</span>
                      </span>
                    </td>
                    <td style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {c.title || '—'}
                    </td>
                    <td>
                      {c.analyst ? (
                        <div className="assigned-cell">
                          <div className="avatar-xs">
                            {c.analyst.slice(0, 2).toUpperCase()}
                          </div>
                          {c.analyst}
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
                      <span className={`badge ${getStatusBadgeClass(c.status)}`}>
                        {c.status || 'open'}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}>
                      {formatDate(c.created_at)}
                    </td>
                    {canEdit && (
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

function getStatusBadgeClass(status) {
  switch (status) {
    case 'open': return 'badge-high'
    case 'investigating': return 'badge-medium'
    case 'contained': return 'badge-status'
    case 'closed': return 'badge-low'
    default: return 'badge-neutral'
  }
}
