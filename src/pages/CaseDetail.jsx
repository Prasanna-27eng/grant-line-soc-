import React, { useEffect, useState } from 'react'
import {
  doc, getDoc, onSnapshot, collection, query, where, orderBy,
  addDoc, deleteDoc, updateDoc, serverTimestamp
} from 'firebase/firestore'
import { db } from '../firebase'
import { useAuth } from '../AuthContext'
import { useParams, useNavigate, Link } from 'react-router-dom'
import jsPDF from 'jspdf'
import autoTable from 'jspdf-autotable'
import { generateCaseSummary, explainIOC } from '../aiUtils'

const TABS = ['IOCs', 'Commands', 'Tools', 'Findings']

// ─── VIRUSTOTAL ──────────────────────────────────────────────────────────
const VT_API_KEY = import.meta.env.VITE_VT_API_KEY

async function enrichIOC(value, type) {
  let url = null

  if (type === 'ip') {
    url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(value)}`
  } else if (type === 'domain') {
    url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(value)}`
  } else if (type === 'hash') {
    url = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(value)}`
  } else if (type === 'url') {
    // VT URL lookup requires base64url-encoded URL (no padding)
    const encoded = btoa(value).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
    url = `https://www.virustotal.com/api/v3/urls/${encoded}`
  } else {
    return { verdict: 'unsupported', malicious: 0, suspicious: 0, total: 0, scanned_at: new Date().toISOString() }
  }

  const res = await fetch(url, {
    headers: { 'x-apikey': VT_API_KEY }
  })

  if (res.status === 404) {
    return { verdict: 'not_found', malicious: 0, suspicious: 0, total: 0, scanned_at: new Date().toISOString() }
  }
  if (!res.ok) {
    throw new Error(`VT API error: ${res.status}`)
  }

  const json = await res.json()
  const stats = json?.data?.attributes?.last_analysis_stats || {}
  const malicious = stats.malicious || 0
  const suspicious = stats.suspicious || 0
  const total = Object.values(stats).reduce((a, b) => a + b, 0)
  const verdict = malicious > 0 ? 'malicious' : suspicious > 0 ? 'suspicious' : 'clean'

  return { verdict, malicious, suspicious, total, scanned_at: new Date().toISOString() }
}

function VTBadge({ result }) {
  if (!result) return null

  const config = {
    malicious:   { label: `⚠ Malicious`,   className: 'vt-malicious' },
    suspicious:  { label: `⚡ Suspicious`,  className: 'vt-suspicious' },
    clean:       { label: `✓ Clean`,        className: 'vt-clean' },
    not_found:   { label: `? Not Found`,    className: 'vt-unknown' },
    unsupported: { label: `— N/A`,          className: 'vt-unknown' },
    error:       { label: `✕ Error`,        className: 'vt-error' },
  }

  const { label, className } = config[result.verdict] || config.error
  const ratio = (result.verdict === 'malicious' || result.verdict === 'suspicious') && result.total > 0
    ? ` ${result.malicious + result.suspicious}/${result.total}`
    : ''

  return (
    <span className={`vt-badge ${className}`} title={`Scanned: ${result.scanned_at?.slice(0, 10)}`}>
      {label}{ratio}
    </span>
  )
}

function formatDate(ts) {
  if (!ts) return '—'
  const d = ts.toDate ? ts.toDate() : new Date(ts)
  return d.toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function formatDateShort(ts) {
  if (!ts) return '—'
  const d = ts.toDate ? ts.toDate() : new Date(ts)
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function getSevBadgeClass(sev) {
  const map = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' }
  return map[sev] || 'badge-neutral'
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

// ─── IOC TAB ────────────────────────────────────────────────────────────
function IOCTab({ caseId, isAnalyst }) {
  const [iocs, setIocs] = useState([])
  const [form, setForm] = useState({ value: '', type: 'ip', description: '', risk_level: 'medium', tags: '' })
  const [showForm, setShowForm] = useState(false)
  const [saving, setSaving] = useState(false)
  const [enriching, setEnriching] = useState({})
  const [vtError, setVtError] = useState({})
  const [explaining, setExplaining] = useState({})
  const [explanations, setExplanations] = useState({})
  const [showExplain, setShowExplain] = useState({})

  useEffect(() => {
    const q = query(collection(db, 'iocs'), where('case_id', '==', caseId), orderBy('created_at', 'desc'))
    return onSnapshot(q, snap => setIocs(snap.docs.map(d => ({ id: d.id, ...d.data() }))))
  }, [caseId])

  const handleAdd = async (e) => {
    e.preventDefault()
    if (!form.value.trim()) return
    setSaving(true)
    try {
      await addDoc(collection(db, 'iocs'), {
        case_id: caseId,
        value: form.value.trim(),
        type: form.type,
        description: form.description.trim(),
        risk_level: form.risk_level,
        tags: form.tags.split(',').map(t => t.trim()).filter(Boolean),
        created_at: serverTimestamp(),
      })
      setForm({ value: '', type: 'ip', description: '', risk_level: 'medium', tags: '' })
      setShowForm(false)
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (id) => {
    if (!confirm('Delete this IOC?')) return
    await deleteDoc(doc(db, 'iocs', id))
  }

  const handleEnrich = async (ioc) => {
    setEnriching(p => ({ ...p, [ioc.id]: true }))
    setVtError(p => ({ ...p, [ioc.id]: null }))
    try {
      const result = await enrichIOC(ioc.value, ioc.type)
      await updateDoc(doc(db, 'iocs', ioc.id), { vt_result: result })
    } catch (err) {
      const errResult = { verdict: 'error', malicious: 0, suspicious: 0, total: 0, scanned_at: new Date().toISOString() }
      await updateDoc(doc(db, 'iocs', ioc.id), { vt_result: errResult })
      setVtError(p => ({ ...p, [ioc.id]: err.message }))
    } finally {
      setEnriching(p => ({ ...p, [ioc.id]: false }))
    }
  }

  const handleExplainIOC = async (ioc) => {
    // Toggle off if already showing
    if (showExplain[ioc.id]) {
      setShowExplain(p => ({ ...p, [ioc.id]: false }))
      return
    }
    // Use cached result if available
    if (explanations[ioc.id]) {
      setShowExplain(p => ({ ...p, [ioc.id]: true }))
      return
    }
    setExplaining(p => ({ ...p, [ioc.id]: true }))
    setShowExplain(p => ({ ...p, [ioc.id]: true }))
    try {
      const text = await explainIOC({
        value: ioc.value,
        type: ioc.type,
        risk_level: ioc.risk_level,
        vt_result: ioc.vt_result || null,
      })
      setExplanations(p => ({ ...p, [ioc.id]: text }))
    } catch (err) {
      setExplanations(p => ({ ...p, [ioc.id]: `AI error: ${err.message}` }))
    } finally {
      setExplaining(p => ({ ...p, [ioc.id]: false }))
    }
  }

  const colCount = isAnalyst ? 7 : 6

  return (
    <div>
      {isAnalyst && (
        <div style={{ padding: '12px 20px', borderBottom: '1px solid var(--border)' }}>
          <button className="btn-secondary" style={{ fontSize: 12 }} onClick={() => setShowForm(!showForm)}>
            {showForm ? '✕ Cancel' : '+ Add IOC'}
          </button>
          {showForm && (
            <form onSubmit={handleAdd} className="inline-form" style={{ marginTop: 12 }}>
              <div className="inline-form-row">
                <div className="form-group">
                  <label className="form-label">Value *</label>
                  <input
                    placeholder="192.168.1.1 / evil.com / hash..."
                    value={form.value}
                    onChange={e => setForm(p => ({ ...p, value: e.target.value }))}
                    style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12 }}
                    required
                  />
                </div>
                <div className="form-group" style={{ flex: '0 0 120px' }}>
                  <label className="form-label">Type</label>
                  <select value={form.type} onChange={e => setForm(p => ({ ...p, type: e.target.value }))}>
                    <option value="ip">IP</option>
                    <option value="domain">Domain</option>
                    <option value="url">URL</option>
                    <option value="hash">Hash</option>
                    <option value="email">Email</option>
                    <option value="filename">Filename</option>
                  </select>
                </div>
                <div className="form-group" style={{ flex: '0 0 120px' }}>
                  <label className="form-label">Risk Level</label>
                  <select value={form.risk_level} onChange={e => setForm(p => ({ ...p, risk_level: e.target.value }))}>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="unknown">Unknown</option>
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Description</label>
                  <input
                    placeholder="Brief description..."
                    value={form.description}
                    onChange={e => setForm(p => ({ ...p, description: e.target.value }))}
                  />
                </div>
                <div style={{ paddingBottom: 16, alignSelf: 'flex-end' }}>
                  <button type="submit" className="btn-primary" disabled={saving}>
                    {saving ? '...' : 'Add'}
                  </button>
                </div>
              </div>
            </form>
          )}
        </div>
      )}
      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Value</th>
              <th>Type</th>
              <th>Risk</th>
              <th>VT Verdict</th>
              <th>Description</th>
              <th>Added</th>
              {isAnalyst && <th style={{ width: 100 }}></th>}
            </tr>
          </thead>
          <tbody>
            {iocs.length === 0 ? (
              <tr><td colSpan={colCount}>
                <div className="empty-state"><span className="empty-state-icon">🔗</span><span className="empty-state-text">No IOCs logged</span></div>
              </td></tr>
            ) : iocs.map(ioc => (
              <React.Fragment key={ioc.id}>
                <tr>
                  <td><span className="ioc-value">{ioc.value}</span></td>
                  <td><span className="ioc-type-pill">{ioc.type}</span></td>
                  <td><span className={`badge ${getSevBadgeClass(ioc.risk_level)}`}>{ioc.risk_level}</span></td>
                  <td>
                    {enriching[ioc.id] ? (
                      <span className="vt-badge vt-scanning">⟳ Scanning...</span>
                    ) : ioc.vt_result ? (
                      <VTBadge result={ioc.vt_result} />
                    ) : (
                      <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>
                    )}
                  </td>
                  <td style={{ color: 'var(--text-secondary)', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ioc.description || '—'}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}>{formatDateShort(ioc.created_at)}</td>
                  {isAnalyst && (
                    <td>
                      <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                        <button
                          className="btn-icon vt-enrich-btn"
                          onClick={() => handleEnrich(ioc)}
                          disabled={enriching[ioc.id]}
                          title={`Enrich with VirusTotal${ioc.vt_result ? ' (re-scan)' : ''}`}
                        >
                          {enriching[ioc.id] ? '⟳' : '🛡'}
                        </button>
                        <button
                          className="btn-icon ai-explain-btn"
                          onClick={() => handleExplainIOC(ioc)}
                          disabled={explaining[ioc.id]}
                          title="AI: Explain this IOC"
                          style={{ color: showExplain[ioc.id] ? 'var(--accent)' : undefined }}
                        >
                          {explaining[ioc.id] ? '⟳' : '🤖'}
                        </button>
                        <button className="btn-icon" onClick={() => handleDelete(ioc.id)} title="Delete IOC" style={{ color: 'var(--sev-critical)' }}>✕</button>
                      </div>
                    </td>
                  )}
                </tr>
                {showExplain[ioc.id] && (
                  <tr>
                    <td colSpan={colCount} style={{ padding: 0, borderBottom: '1px solid var(--border)' }}>
                      <div className="ai-explain-panel">
                        <div className="ai-explain-header">
                          <span className="ai-label">🤖 AI Intel — {ioc.value}</span>
                          <button className="btn-icon" style={{ fontSize: 11 }} onClick={() => setShowExplain(p => ({ ...p, [ioc.id]: false }))}>✕</button>
                        </div>
                        {explaining[ioc.id] ? (
                          <div className="ai-thinking">Analysing IOC with threat intelligence...</div>
                        ) : (
                          <div className="ai-explain-body">{explanations[ioc.id]}</div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
      <div style={{ padding: '8px 20px', fontSize: 11, color: 'var(--text-muted)', borderTop: '1px solid var(--border)' }}>
        🛡 Click the shield icon on any IOC to query VirusTotal across 90+ AV engines. Results are saved automatically.
      </div>
    </div>
  )
}

// ─── COMMANDS TAB ─────────────────────────────────────────────────────────
function CommandsTab({ caseId, isAnalyst }) {
  const [commands, setCommands] = useState([])
  const [form, setForm] = useState({ command: '', purpose: '', tool: '', output: '' })
  const [showForm, setShowForm] = useState(false)
  const [saving, setSaving] = useState(false)
  const [expanded, setExpanded] = useState({})

  useEffect(() => {
    const q = query(collection(db, 'commands'), where('case_id', '==', caseId), orderBy('created_at', 'desc'))
    return onSnapshot(q, snap => setCommands(snap.docs.map(d => ({ id: d.id, ...d.data() }))))
  }, [caseId])

  const handleAdd = async (e) => {
    e.preventDefault()
    if (!form.command.trim()) return
    setSaving(true)
    try {
      await addDoc(collection(db, 'commands'), {
        case_id: caseId,
        command: form.command.trim(),
        purpose: form.purpose.trim(),
        tool: form.tool.trim(),
        output: form.output.trim(),
        created_at: serverTimestamp(),
      })
      setForm({ command: '', purpose: '', tool: '', output: '' })
      setShowForm(false)
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (id) => {
    if (!confirm('Delete this command?')) return
    await deleteDoc(doc(db, 'commands', id))
  }

  return (
    <div>
      {isAnalyst && (
        <div style={{ padding: '12px 20px', borderBottom: '1px solid var(--border)' }}>
          <button className="btn-secondary" style={{ fontSize: 12 }} onClick={() => setShowForm(!showForm)}>
            {showForm ? '✕ Cancel' : '+ Log Command'}
          </button>
          {showForm && (
            <form onSubmit={handleAdd} className="inline-form" style={{ marginTop: 12 }}>
              <div className="form-group">
                <label className="form-label">Command *</label>
                <input
                  placeholder="nmap -sV -p 1-65535 192.168.1.100"
                  value={form.command}
                  onChange={e => setForm(p => ({ ...p, command: e.target.value }))}
                  style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12 }}
                  required
                />
              </div>
              <div className="inline-form-row">
                <div className="form-group">
                  <label className="form-label">Purpose</label>
                  <input placeholder="Port scan for service enumeration" value={form.purpose} onChange={e => setForm(p => ({ ...p, purpose: e.target.value }))} />
                </div>
                <div className="form-group" style={{ flex: '0 0 160px' }}>
                  <label className="form-label">Tool</label>
                  <input placeholder="nmap" value={form.tool} onChange={e => setForm(p => ({ ...p, tool: e.target.value }))} />
                </div>
              </div>
              <div className="form-group">
                <label className="form-label">Output</label>
                <textarea placeholder="Command output / results..." value={form.output} onChange={e => setForm(p => ({ ...p, output: e.target.value }))} rows={3} />
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button type="submit" className="btn-primary" disabled={saving}>{saving ? '...' : 'Log Command'}</button>
                <button type="button" className="btn-secondary" onClick={() => setShowForm(false)}>Cancel</button>
              </div>
            </form>
          )}
        </div>
      )}
      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Command</th>
              <th>Purpose</th>
              <th>Tool</th>
              <th>Output</th>
              <th>Logged</th>
              {isAnalyst && <th style={{ width: 60 }}></th>}
            </tr>
          </thead>
          <tbody>
            {commands.length === 0 ? (
              <tr><td colSpan={isAnalyst ? 6 : 5}>
                <div className="empty-state"><span className="empty-state-icon">⚡</span><span className="empty-state-text">No commands logged</span></div>
              </td></tr>
            ) : commands.map(cmd => (
              <tr key={cmd.id}>
                <td style={{ maxWidth: 260 }}>
                  <div className="command-block">{cmd.command}</div>
                </td>
                <td style={{ color: 'var(--text-secondary)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cmd.purpose || '—'}</td>
                <td>
                  {cmd.tool ? <span className="badge badge-neutral">{cmd.tool}</span> : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                </td>
                <td style={{ maxWidth: 200 }}>
                  {cmd.output ? (
                    <div>
                      <div
                        style={{
                          fontFamily: 'JetBrains Mono, monospace',
                          fontSize: 10,
                          color: 'var(--text-muted)',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: expanded[cmd.id] ? 'pre-wrap' : 'nowrap',
                          maxWidth: 200,
                          cursor: 'pointer',
                        }}
                        onClick={() => setExpanded(p => ({ ...p, [cmd.id]: !p[cmd.id] }))}
                      >
                        {cmd.output}
                      </div>
                    </div>
                  ) : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                </td>
                <td style={{ color: 'var(--text-muted)', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}>{formatDateShort(cmd.created_at)}</td>
                {isAnalyst && (
                  <td>
                    <button className="btn-icon" onClick={() => handleDelete(cmd.id)} style={{ color: 'var(--sev-critical)' }} title="Delete">✕</button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── TOOLS TAB ─────────────────────────────────────────────────────────
function ToolsTab({ caseId, isAnalyst }) {
  const [tools, setTools] = useState([])
  const [form, setForm] = useState({ name: '', category: 'forensics', purpose: '', notes: '' })
  const [showForm, setShowForm] = useState(false)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    const q = query(collection(db, 'tools'), where('case_id', '==', caseId), orderBy('created_at', 'desc'))
    return onSnapshot(q, snap => setTools(snap.docs.map(d => ({ id: d.id, ...d.data() }))))
  }, [caseId])

  const handleAdd = async (e) => {
    e.preventDefault()
    if (!form.name.trim()) return
    setSaving(true)
    try {
      await addDoc(collection(db, 'tools'), {
        case_id: caseId,
        name: form.name.trim(),
        category: form.category,
        purpose: form.purpose.trim(),
        notes: form.notes.trim(),
        created_at: serverTimestamp(),
      })
      setForm({ name: '', category: 'forensics', purpose: '', notes: '' })
      setShowForm(false)
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (id) => {
    if (!confirm('Delete this tool entry?')) return
    await deleteDoc(doc(db, 'tools', id))
  }

  const CATEGORIES = ['forensics', 'network', 'malware-analysis', 'recon', 'detection', 'response', 'osint', 'other']

  return (
    <div>
      {isAnalyst && (
        <div style={{ padding: '12px 20px', borderBottom: '1px solid var(--border)' }}>
          <button className="btn-secondary" style={{ fontSize: 12 }} onClick={() => setShowForm(!showForm)}>
            {showForm ? '✕ Cancel' : '+ Add Tool'}
          </button>
          {showForm && (
            <form onSubmit={handleAdd} className="inline-form" style={{ marginTop: 12 }}>
              <div className="inline-form-row">
                <div className="form-group">
                  <label className="form-label">Tool Name *</label>
                  <input placeholder="Volatility3" value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} required />
                </div>
                <div className="form-group" style={{ flex: '0 0 160px' }}>
                  <label className="form-label">Category</label>
                  <select value={form.category} onChange={e => setForm(p => ({ ...p, category: e.target.value }))}>
                    {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>
              </div>
              <div className="form-group">
                <label className="form-label">Purpose</label>
                <input placeholder="Memory forensics and artifact extraction" value={form.purpose} onChange={e => setForm(p => ({ ...p, purpose: e.target.value }))} />
              </div>
              <div className="form-group">
                <label className="form-label">Notes</label>
                <textarea placeholder="Usage notes, version, configuration..." value={form.notes} onChange={e => setForm(p => ({ ...p, notes: e.target.value }))} rows={2} />
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button type="submit" className="btn-primary" disabled={saving}>{saving ? '...' : 'Add Tool'}</button>
                <button type="button" className="btn-secondary" onClick={() => setShowForm(false)}>Cancel</button>
              </div>
            </form>
          )}
        </div>
      )}
      {tools.length === 0 ? (
        <div className="empty-state"><span className="empty-state-icon">🛠</span><span className="empty-state-text">No tools documented</span></div>
      ) : (
        <div className="tools-grid">
          {tools.map(t => (
            <div key={t.id} className="tool-card">
              {isAnalyst && (
                <div className="tool-card-actions">
                  <button className="btn-icon" onClick={() => handleDelete(t.id)} style={{ color: 'var(--sev-critical)' }} title="Delete">✕</button>
                </div>
              )}
              <div className="tool-card-name">{t.name}</div>
              <span className="badge badge-neutral" style={{ fontSize: 10 }}>{t.category}</span>
              {t.purpose && <div className="tool-card-purpose">{t.purpose}</div>}
              {t.notes && <div className="tool-card-notes">{t.notes}</div>}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── FINDINGS TAB ───────────────────────────────────────────────────────
function FindingsTab({ caseId, isAnalyst }) {
  const [findings, setFindings] = useState([])
  const [form, setForm] = useState({ title: '', description: '', evidence: '', mitre_technique: '', severity: 'medium', timestamp: '' })
  const [showForm, setShowForm] = useState(false)
  const [saving, setSaving] = useState(false)
  const [expandEvidence, setExpandEvidence] = useState({})

  useEffect(() => {
    const q = query(collection(db, 'findings'), where('case_id', '==', caseId), orderBy('timestamp', 'desc'))
    return onSnapshot(q, snap => setFindings(snap.docs.map(d => ({ id: d.id, ...d.data() }))))
  }, [caseId])

  const handleAdd = async (e) => {
    e.preventDefault()
    if (!form.title.trim()) return
    setSaving(true)
    try {
      const tsDate = form.timestamp ? new Date(form.timestamp) : new Date()
      await addDoc(collection(db, 'findings'), {
        case_id: caseId,
        title: form.title.trim(),
        description: form.description.trim(),
        evidence: form.evidence.trim(),
        mitre_technique: form.mitre_technique.trim(),
        severity: form.severity,
        timestamp: tsDate,
        created_at: serverTimestamp(),
      })
      setForm({ title: '', description: '', evidence: '', mitre_technique: '', severity: 'medium', timestamp: '' })
      setShowForm(false)
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (id) => {
    if (!confirm('Delete this finding?')) return
    await deleteDoc(doc(db, 'findings', id))
  }

  return (
    <div>
      {isAnalyst && (
        <div style={{ padding: '12px 20px', borderBottom: '1px solid var(--border)' }}>
          <button className="btn-secondary" style={{ fontSize: 12 }} onClick={() => setShowForm(!showForm)}>
            {showForm ? '✕ Cancel' : '+ Add Finding'}
          </button>
          {showForm && (
            <form onSubmit={handleAdd} className="inline-form" style={{ marginTop: 12 }}>
              <div className="inline-form-row">
                <div className="form-group">
                  <label className="form-label">Title *</label>
                  <input placeholder="Malicious process injection detected" value={form.title} onChange={e => setForm(p => ({ ...p, title: e.target.value }))} required />
                </div>
                <div className="form-group" style={{ flex: '0 0 120px' }}>
                  <label className="form-label">Severity</label>
                  <select value={form.severity} onChange={e => setForm(p => ({ ...p, severity: e.target.value }))}>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div className="form-group" style={{ flex: '0 0 160px' }}>
                  <label className="form-label">MITRE Technique</label>
                  <input placeholder="T1055.001" value={form.mitre_technique} onChange={e => setForm(p => ({ ...p, mitre_technique: e.target.value }))} />
                </div>
                <div className="form-group" style={{ flex: '0 0 190px' }}>
                  <label className="form-label">Timestamp</label>
                  <input type="datetime-local" value={form.timestamp} onChange={e => setForm(p => ({ ...p, timestamp: e.target.value }))} />
                </div>
              </div>
              <div className="form-group">
                <label className="form-label">Description</label>
                <textarea placeholder="Detailed finding description..." value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} rows={2} />
              </div>
              <div className="form-group">
                <label className="form-label">Evidence</label>
                <textarea placeholder="Log snippets, file hashes, memory artifacts..." value={form.evidence} onChange={e => setForm(p => ({ ...p, evidence: e.target.value }))} rows={2} />
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button type="submit" className="btn-primary" disabled={saving}>{saving ? '...' : 'Add Finding'}</button>
                <button type="button" className="btn-secondary" onClick={() => setShowForm(false)}>Cancel</button>
              </div>
            </form>
          )}
        </div>
      )}
      {findings.length === 0 ? (
        <div className="empty-state"><span className="empty-state-icon">◉</span><span className="empty-state-text">No findings documented</span></div>
      ) : (
        findings.map(f => (
          <div key={f.id} className="finding-item">
            <div className="finding-header">
              <span className="finding-title">{f.title}</span>
              <span className={`badge ${getSevBadgeClass(f.severity)}`}>{f.severity}</span>
              {f.mitre_technique && <span className="mitre-pill">{f.mitre_technique}</span>}
              {isAnalyst && (
                <button className="btn-icon" onClick={() => handleDelete(f.id)} style={{ color: 'var(--sev-critical)', marginLeft: 'auto' }}>✕</button>
              )}
            </div>
            {f.description && <div className="finding-body">{f.description}</div>}
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
        ))
      )}
    </div>
  )
}

// ─── PDF EXPORT ─────────────────────────────────────────────────────────
async function generatePDF(caseData, iocs, commands, toolsList, findings, incId) {
  const pdf = new jsPDF({ orientation: 'p', unit: 'pt', format: 'a4' })
  const W = pdf.internal.pageSize.getWidth()

  const darkBg = [13, 17, 23]
  const surfaceBg = [22, 27, 34]
  const accentColor = [56, 189, 248]
  const textPrimary = [230, 237, 243]
  const textSecondary = [139, 148, 158]
  const borderColor = [33, 38, 45]

  const addPage = () => {
    pdf.addPage()
    pdf.setFillColor(...darkBg)
    pdf.rect(0, 0, W, pdf.internal.pageSize.getHeight(), 'F')
  }

  const setPage = () => {
    pdf.setFillColor(...darkBg)
    pdf.rect(0, 0, W, pdf.internal.pageSize.getHeight(), 'F')
  }

  // ── Cover Page
  setPage()
  pdf.setFillColor(...surfaceBg)
  pdf.roundedRect(40, 60, W - 80, 120, 6, 6, 'F')

  pdf.setTextColor(...accentColor)
  pdf.setFontSize(10)
  pdf.setFont('helvetica', 'normal')
  pdf.text('Grand Line SOC — Incident Report', 56, 88)

  pdf.setTextColor(...textPrimary)
  pdf.setFontSize(22)
  pdf.setFont('helvetica', 'bold')
  pdf.text(incId, 56, 118)

  pdf.setFontSize(13)
  pdf.setFont('helvetica', 'normal')
  pdf.setTextColor(...textSecondary)
  const titleLines = pdf.splitTextToSize(caseData.title || '', W - 112)
  pdf.text(titleLines, 56, 140)

  let y = 210
  const field = (label, value) => {
    pdf.setFontSize(9)
    pdf.setTextColor(...textSecondary)
    pdf.text(label.toUpperCase(), 56, y)
    pdf.setTextColor(...textPrimary)
    pdf.setFontSize(11)
    pdf.text(String(value || '—'), 56, y + 14)
    y += 38
  }

  field('Severity', (caseData.severity || '').toUpperCase())
  field('Status', (caseData.status || '').toUpperCase())
  field('Lead Analyst', caseData.analyst || '—')
  field('Created', caseData.created_at?.toDate ? caseData.created_at.toDate().toLocaleString() : '—')

  if (caseData.mitre_tactics?.length) {
    pdf.setFontSize(9)
    pdf.setTextColor(...textSecondary)
    pdf.text('MITRE ATT&CK TACTICS', 56, y)
    y += 14
    pdf.setFontSize(10)
    pdf.setTextColor(...accentColor)
    pdf.text(caseData.mitre_tactics.join(' · '), 56, y)
    y += 28
  }

  if (caseData.description) {
    pdf.setFontSize(9)
    pdf.setTextColor(...textSecondary)
    pdf.text('DESCRIPTION', 56, y)
    y += 14
    pdf.setFontSize(10)
    pdf.setTextColor(...textPrimary)
    const desc = pdf.splitTextToSize(caseData.description, W - 112)
    pdf.text(desc, 56, y)
    y += desc.length * 14 + 16
  }

  if (caseData.notes) {
    pdf.setFontSize(9)
    pdf.setTextColor(...textSecondary)
    pdf.text('NOTES', 56, y)
    y += 14
    pdf.setFontSize(10)
    pdf.setTextColor(...textPrimary)
    const notes = pdf.splitTextToSize(caseData.notes, W - 112)
    pdf.text(notes, 56, y)
  }

  const tableStyles = {
    theme: 'plain',
    styles: {
      fillColor: surfaceBg,
      textColor: textPrimary,
      fontSize: 9,
      cellPadding: 6,
      lineColor: borderColor,
      lineWidth: 0.5,
    },
    headStyles: {
      fillColor: [28, 35, 51],
      textColor: textSecondary,
      fontSize: 8,
      fontStyle: 'bold',
    },
    alternateRowStyles: { fillColor: [19, 24, 31] },
  }

  const pageTitle = (title) => {
    pdf.setFillColor(...surfaceBg)
    pdf.rect(40, 40, W - 80, 36, 'F')
    pdf.setTextColor(...accentColor)
    pdf.setFontSize(14)
    pdf.setFont('helvetica', 'bold')
    pdf.text(title, 56, 64)
    pdf.setTextColor(...textSecondary)
    pdf.setFontSize(9)
    pdf.setFont('helvetica', 'normal')
    pdf.text(incId, W - 56, 64, { align: 'right' })
  }

  // ── IOCs
  addPage()
  pageTitle('Indicators of Compromise')
  autoTable(pdf, {
    startY: 96,
    head: [['Value', 'Type', 'Risk Level', 'Description']],
    body: iocs.map(i => [i.value, i.type, i.risk_level, i.description || '']),
    ...tableStyles,
  })

  // ── Findings
  addPage()
  pageTitle('Findings')
  autoTable(pdf, {
    startY: 96,
    head: [['Title', 'Severity', 'MITRE', 'Description', 'Timestamp']],
    body: findings.map(f => [
      f.title,
      f.severity,
      f.mitre_technique || '',
      f.description || '',
      f.timestamp?.toDate ? f.timestamp.toDate().toLocaleString() : '—',
    ]),
    ...tableStyles,
    columnStyles: { 3: { cellWidth: 140 } },
  })

  // ── Commands
  addPage()
  pageTitle('Commands Executed')
  autoTable(pdf, {
    startY: 96,
    head: [['Command', 'Purpose', 'Tool', 'Output']],
    body: commands.map(c => [c.command, c.purpose || '', c.tool || '', c.output || '']),
    ...tableStyles,
    columnStyles: { 0: { fontStyle: 'normal', font: 'courier' } },
  })

  // ── Tools
  addPage()
  pageTitle('Tools Used')
  autoTable(pdf, {
    startY: 96,
    head: [['Name', 'Category', 'Purpose', 'Notes']],
    body: toolsList.map(t => [t.name, t.category, t.purpose || '', t.notes || '']),
    ...tableStyles,
  })

  pdf.save(`${incId}-report.pdf`)
}

// ─── MAIN COMPONENT ────────────────────────────────────────────────────
export default function CaseDetail() {
  const { id } = useParams()
  const { isAnalyst, canEdit, canDelete } = useAuth()
  const navigate = useNavigate()
  const [caseData, setCaseData] = useState(null)
  const [iocs, setIocs] = useState([])
  const [commands, setCommands] = useState([])
  const [toolsList, setToolsList] = useState([])
  const [findings, setFindings] = useState([])
  const [activeTab, setActiveTab] = useState('IOCs')
  const [status, setStatus] = useState('')
  const [saving, setSaving] = useState(false)
  const [notFound, setNotFound] = useState(false)
  const [aiSummary, setAiSummary] = useState('')
  const [aiSummaryLoading, setAiSummaryLoading] = useState(false)
  const [showAiSummary, setShowAiSummary] = useState(false)

  // case index for INC id
  const [caseIdx, setCaseIdx] = useState(0)

  useEffect(() => {
    const unsub = onSnapshot(doc(db, 'cases', id), (snap) => {
      if (!snap.exists()) { setNotFound(true); return }
      const data = { id: snap.id, ...snap.data() }
      setCaseData(data)
      setStatus(data.status || 'open')
    })
    return unsub
  }, [id])

  // sub-collections live listeners for PDF
  useEffect(() => {
    if (!id) return
    const q1 = query(collection(db, 'iocs'), where('case_id', '==', id))
    const u1 = onSnapshot(q1, s => setIocs(s.docs.map(d => ({ id: d.id, ...d.data() }))))
    const q2 = query(collection(db, 'commands'), where('case_id', '==', id))
    const u2 = onSnapshot(q2, s => setCommands(s.docs.map(d => ({ id: d.id, ...d.data() }))))
    const q3 = query(collection(db, 'tools'), where('case_id', '==', id))
    const u3 = onSnapshot(q3, s => setToolsList(s.docs.map(d => ({ id: d.id, ...d.data() }))))
    const q4 = query(collection(db, 'findings'), where('case_id', '==', id))
    const u4 = onSnapshot(q4, s => setFindings(s.docs.map(d => ({ id: d.id, ...d.data() }))))
    return () => { u1(); u2(); u3(); u4() }
  }, [id])

  const handleUpdateStatus = async () => {
    setSaving(true)
    try {
      await updateDoc(doc(db, 'cases', id), { status, updated_at: serverTimestamp() })
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!confirm('Delete this case and all associated data?')) return
    await deleteDoc(doc(db, 'cases', id))
    navigate('/cases')
  }

  const handleDownloadPDF = () => {
    generatePDF(caseData, iocs, commands, toolsList, findings, `INC-${id.slice(-4).toUpperCase()}`)
  }

  const handleAISummary = async () => {
    if (showAiSummary && aiSummary) { setShowAiSummary(false); return }
    setShowAiSummary(true)
    if (aiSummary) return // already generated, just re-show
    setAiSummaryLoading(true)
    try {
      const text = await generateCaseSummary({ caseData, iocs, findings, commands })
      setAiSummary(text)
    } catch (err) {
      setAiSummary(`AI error: ${err.message}`)
    } finally {
      setAiSummaryLoading(false)
    }
  }

  if (notFound) {
    return (
      <div className="empty-state">
        <span className="empty-state-icon">◈</span>
        <span className="empty-state-text">Case not found</span>
        <Link to="/cases" className="btn-secondary" style={{ textDecoration: 'none', marginTop: 8 }}>Back to Cases</Link>
      </div>
    )
  }

  if (!caseData) {
    return (
      <div className="empty-state">
        <span className="empty-state-icon">⚓</span>
        <span className="empty-state-text">Loading...</span>
      </div>
    )
  }

  const incId = `INC-${id.slice(-4).toUpperCase()}`

  return (
    <div>
      {/* Breadcrumb */}
      <div style={{ marginBottom: 16, fontSize: 12, color: 'var(--text-muted)' }}>
        <Link to="/cases" style={{ color: 'var(--text-muted)', textDecoration: 'none' }}>Incident Queue</Link>
        <span style={{ margin: '0 6px' }}>›</span>
        <span style={{ color: 'var(--accent)', fontFamily: 'JetBrains Mono, monospace' }}>{incId}</span>
      </div>

      {/* Case Header Card */}
      <div className="case-detail-header">
        <div className="case-meta-row">
          <span className="case-id-label">{incId}</span>
          <span className={`badge ${getSevBadgeClass(caseData.severity)}`}>{caseData.severity}</span>
          <span className={`badge ${getStatusBadgeClass(caseData.status)}`}>{caseData.status}</span>
        </div>

        <div className="case-title">{caseData.title}</div>

        {caseData.description && (
          <div className="case-description" style={{ margin: '8px 0', color: 'var(--text-secondary)' }}>
            {caseData.description}
          </div>
        )}

        {caseData.mitre_tactics?.length > 0 && (
          <div className="tactic-list" style={{ margin: '10px 0' }}>
            {caseData.mitre_tactics.map(t => (
              <span key={t} className="mitre-pill">{t}</span>
            ))}
            {caseData.mitre_techniques?.map(t => (
              <span key={t} className="mitre-pill" style={{ opacity: 0.7 }}>{t}</span>
            ))}
          </div>
        )}

        <div className="case-footer-row">
          {caseData.analyst && (
            <div className="case-footer-item">
              <div className="avatar-xs">{caseData.analyst.slice(0, 2).toUpperCase()}</div>
              {caseData.analyst}
            </div>
          )}
          <div className="case-footer-item">
            <span>Created</span>
            {formatDate(caseData.created_at)}
          </div>
          {caseData.updated_at && (
            <div className="case-footer-item">
              <span>Updated</span>
              {formatDate(caseData.updated_at)}
            </div>
          )}
          {caseData.tags?.length > 0 && (
            <div className="case-footer-item" style={{ gap: 4 }}>
              {caseData.tags.map(t => (
                <span key={t} className="badge badge-neutral" style={{ fontSize: 10 }}>{t}</span>
              ))}
            </div>
          )}
        </div>

        {(canEdit || canDelete) && (
          <div className="case-actions-row">
            {canEdit && (
              <>
                <select
                  className="status-select"
                  value={status}
                  onChange={e => setStatus(e.target.value)}
                >
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="contained">Contained</option>
                  <option value="closed">Closed</option>
                </select>
                <button className="btn-primary" onClick={handleUpdateStatus} disabled={saving}>
                  {saving ? 'Saving...' : 'Update Status'}
                </button>
              </>
            )}
            <button
              className="btn-secondary ai-summary-btn"
              onClick={handleAISummary}
              disabled={aiSummaryLoading}
              style={{ borderColor: showAiSummary ? 'var(--accent)' : undefined, color: showAiSummary ? 'var(--accent)' : undefined }}
            >
              {aiSummaryLoading ? '⟳ Generating...' : '🤖 AI Summary'}
            </button>
            <button className="btn-secondary" onClick={handleDownloadPDF}>
              ⬇ Download PDF
            </button>
            {canDelete && (
              <button className="btn-danger" onClick={handleDelete}>
                ✕ Delete Case
              </button>
            )}
          </div>
        )}
      </div>

      {/* AI Summary Panel */}
      {showAiSummary && (
        <div className="ai-summary-panel">
          <div className="ai-summary-header">
            <span className="ai-label">🤖 AI Executive Summary</span>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {aiSummary && !aiSummaryLoading && (
                <button
                  className="btn-icon"
                  style={{ fontSize: 11, color: 'var(--text-secondary)' }}
                  title="Copy to clipboard"
                  onClick={() => navigator.clipboard.writeText(aiSummary)}
                >
                  📋 Copy
                </button>
              )}
              <button className="btn-icon" style={{ fontSize: 12 }} onClick={() => setShowAiSummary(false)}>✕</button>
            </div>
          </div>
          {aiSummaryLoading ? (
            <div className="ai-thinking">
              Analysing {iocs.length} IOCs, {findings.length} findings, {commands.length} commands...
            </div>
          ) : (
            <div className="ai-summary-body">{aiSummary}</div>
          )}
        </div>
      )}

      {/* Sub-collection Tabs */}
      <div className="table-section">
        <div style={{ padding: '0 4px' }}>
          <div className="tab-bar" style={{ padding: '0 16px', marginBottom: 0 }}>
            {TABS.map(tab => (
              <button
                key={tab}
                className={`tab-item ${activeTab === tab ? 'active' : ''}`}
                onClick={() => setActiveTab(tab)}
              >
                {tab}
                {tab === 'IOCs' && iocs.length > 0 && (
                  <span style={{ marginLeft: 6, background: 'var(--accent-dim)', color: 'var(--accent)', borderRadius: 10, padding: '0 6px', fontSize: 10 }}>
                    {iocs.length}
                  </span>
                )}
                {tab === 'Findings' && findings.length > 0 && (
                  <span style={{ marginLeft: 6, background: 'var(--accent-dim)', color: 'var(--accent)', borderRadius: 10, padding: '0 6px', fontSize: 10 }}>
                    {findings.length}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>

        {activeTab === 'IOCs' && <IOCTab caseId={id} isAnalyst={canEdit} />}
        {activeTab === 'Commands' && <CommandsTab caseId={id} isAnalyst={canEdit} />}
        {activeTab === 'Tools' && <ToolsTab caseId={id} isAnalyst={canEdit} />}
        {activeTab === 'Findings' && <FindingsTab caseId={id} isAnalyst={canEdit} />}
      </div>
    </div>
  )
}
