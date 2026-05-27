import React, { useState } from 'react'
import { collection, addDoc, serverTimestamp } from 'firebase/firestore'
import { db } from '../firebase'
import { useAuth } from '../AuthContext'
import { useNavigate, Link } from 'react-router-dom'
import { suggestSeverityAndTactics } from '../aiUtils'

const MITRE_TACTICS = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
]

export default function NewCase() {
  const { isAnalyst, canEdit, currentUser } = useAuth()
  const navigate = useNavigate()

  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [severity, setSeverity] = useState('medium')
  const [status, setStatus] = useState('open')
  const [analyst, setAnalyst] = useState(currentUser?.email?.split('@')[0] || '')
  const [tags, setTags] = useState('')
  const [notes, setNotes] = useState('')
  const [selectedTactics, setSelectedTactics] = useState([])
  const [techniques, setTechniques] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  // AI Severity Suggester state
  const [suggesting, setSuggesting] = useState(false)
  const [aiSuggestion, setAiSuggestion] = useState(null)
  const [suggestError, setSuggestError] = useState('')

  if (!canEdit) {
    return (
      <div className="empty-state">
        <span className="empty-state-icon">🔒</span>
        <span className="empty-state-text">Sign in to create cases</span>
        <Link to="/login" className="btn-primary" style={{ textDecoration: 'none', marginTop: 8 }}>
          Sign In
        </Link>
      </div>
    )
  }

  const toggleTactic = (tac) => {
    setSelectedTactics(prev =>
      prev.includes(tac) ? prev.filter(t => t !== tac) : [...prev, tac]
    )
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!title.trim()) { setError('Title is required'); return }
    setSaving(true)
    setError('')
    try {
      const tagList = tags.split(',').map(t => t.trim()).filter(Boolean)
      const techList = techniques.split(',').map(t => t.trim()).filter(Boolean)
      const ref = await addDoc(collection(db, 'cases'), {
        title: title.trim(),
        description: description.trim(),
        severity,
        status,
        analyst: analyst.trim(),
        tags: tagList,
        notes: notes.trim(),
        mitre_tactics: selectedTactics,
        mitre_techniques: techList,
        created_at: serverTimestamp(),
        updated_at: serverTimestamp(),
      })
      navigate(`/cases/${ref.id}`)
    } catch (err) {
      setError('Failed to create case: ' + err.message)
      setSaving(false)
    }
  }

  const handleAISuggest = async () => {
    if (!title.trim() && !description.trim()) {
      setSuggestError('Add a title or description first so AI has something to analyse.')
      return
    }
    setSuggestError('')
    setSuggesting(true)
    setAiSuggestion(null)
    try {
      const result = await suggestSeverityAndTactics({ title, description })
      setAiSuggestion(result)
    } catch (err) {
      setSuggestError(`AI error: ${err.message}`)
    } finally {
      setSuggesting(false)
    }
  }

  const handleApplySuggestion = () => {
    if (!aiSuggestion) return
    setSeverity(aiSuggestion.severity)
    // Merge suggested tactics with any already selected
    const merged = Array.from(new Set([...selectedTactics, ...(aiSuggestion.tactics || [])]))
    setSelectedTactics(merged)
    setAiSuggestion(null)
  }

  const SEV_COLORS = {
    critical: 'var(--sev-critical)',
    high: 'var(--sev-high)',
    medium: 'var(--sev-medium)',
    low: 'var(--sev-low)',
  }

  return (
    <div style={{ maxWidth: 800 }}>
      <div className="page-header">
        <div>
          <div className="page-title">New Incident Brief</div>
          <div className="page-subtitle">Document a new security incident</div>
        </div>
        <div className="page-actions">
          <Link to="/cases" className="btn-secondary" style={{ textDecoration: 'none' }}>
            Cancel
          </Link>
        </div>
      </div>

      {error && (
        <div className="login-error" style={{ marginBottom: 16 }}>{error}</div>
      )}

      <form onSubmit={handleSubmit}>
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 16 }}>
            Core Details
          </div>
          <div className="form-group">
            <label className="form-label">Title *</label>
            <input
              type="text"
              value={title}
              onChange={e => setTitle(e.target.value)}
              placeholder="e.g. Suspicious PowerShell execution on endpoint-07"
              required
            />
          </div>
          <div className="form-grid">
            <div className="form-group">
              <label className="form-label">Severity</label>
              <select value={severity} onChange={e => setSeverity(e.target.value)}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Status</label>
              <select value={status} onChange={e => setStatus(e.target.value)}>
                <option value="open">Open</option>
                <option value="investigating">Investigating</option>
                <option value="contained">Contained</option>
                <option value="closed">Closed</option>
              </select>
            </div>
          </div>
          <div className="form-grid">
            <div className="form-group">
              <label className="form-label">Lead Analyst</label>
              <input
                type="text"
                value={analyst}
                onChange={e => setAnalyst(e.target.value)}
                placeholder="analyst-name"
              />
            </div>
            <div className="form-group">
              <label className="form-label">Tags (comma-separated)</label>
              <input
                type="text"
                value={tags}
                onChange={e => setTags(e.target.value)}
                placeholder="ransomware, endpoint, windows"
              />
            </div>
          </div>

          {/* Description + AI Suggest button */}
          <div className="form-group">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
              <label className="form-label" style={{ marginBottom: 0 }}>Description</label>
              <button
                type="button"
                className="ai-suggest-btn"
                onClick={handleAISuggest}
                disabled={suggesting}
                title="Let AI suggest severity and MITRE tactics based on your title and description"
              >
                {suggesting ? '⟳ Analysing...' : '🤖 AI Suggest Severity & Tactics'}
              </button>
            </div>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Describe the incident, initial indicators, scope, and impact..."
              rows={4}
            />
          </div>

          {/* AI Suggestion result panel */}
          {suggestError && (
            <div style={{ background: 'var(--sev-critical-bg)', border: '1px solid rgba(248,81,73,0.3)', borderRadius: 6, padding: '8px 12px', color: 'var(--sev-critical)', fontSize: 12, marginBottom: 12 }}>
              {suggestError}
            </div>
          )}
          {aiSuggestion && (
            <div className="ai-suggestion-panel">
              <div className="ai-suggestion-header">
                <span className="ai-label">🤖 AI Suggestion</span>
                <button className="btn-icon" style={{ fontSize: 11 }} onClick={() => setAiSuggestion(null)}>✕</button>
              </div>
              <div className="ai-suggestion-body">
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 10 }}>
                  <div>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Suggested Severity</span>
                    <div style={{ marginTop: 4 }}>
                      <span style={{
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: 14,
                        fontWeight: 600,
                        color: SEV_COLORS[aiSuggestion.severity] || 'var(--text-primary)',
                        textTransform: 'uppercase',
                      }}>
                        {aiSuggestion.severity}
                      </span>
                    </div>
                  </div>
                  {aiSuggestion.tactics?.length > 0 && (
                    <div>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Suggested Tactics</span>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
                        {aiSuggestion.tactics.map(t => (
                          <span key={t} className="mitre-pill">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                {aiSuggestion.reason && (
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 12, fontStyle: 'italic' }}>
                    "{aiSuggestion.reason}"
                  </div>
                )}
                <div style={{ display: 'flex', gap: 8 }}>
                  <button type="button" className="btn-primary" style={{ fontSize: 12, padding: '5px 14px' }} onClick={handleApplySuggestion}>
                    ✓ Apply Suggestion
                  </button>
                  <button type="button" className="btn-secondary" style={{ fontSize: 12, padding: '5px 14px' }} onClick={() => setAiSuggestion(null)}>
                    Dismiss
                  </button>
                </div>
              </div>
            </div>
          )}

          <div className="form-group">
            <label className="form-label">Notes</label>
            <textarea
              value={notes}
              onChange={e => setNotes(e.target.value)}
              placeholder="Investigation notes, analyst observations, response actions taken..."
              rows={3}
            />
          </div>
        </div>

        <div className="card" style={{ marginBottom: 16 }}>
          <div style={{ fontWeight: 600, fontSize: 12, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 16 }}>
            MITRE ATT&CK Mapping
          </div>
          <div className="form-group">
            <label className="form-label">Tactics</label>
            <div className="checkbox-grid">
              {MITRE_TACTICS.map(tac => (
                <label key={tac} className="checkbox-item">
                  <input
                    type="checkbox"
                    checked={selectedTactics.includes(tac)}
                    onChange={() => toggleTactic(tac)}
                  />
                  <span style={{ color: selectedTactics.includes(tac) ? 'var(--accent)' : undefined }}>
                    {tac}
                  </span>
                </label>
              ))}
            </div>
          </div>
          <div className="form-group" style={{ marginTop: 16 }}>
            <label className="form-label">Techniques (comma-separated)</label>
            <input
              type="text"
              value={techniques}
              onChange={e => setTechniques(e.target.value)}
              placeholder="T1059.001, T1078, T1486"
            />
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <Link to="/cases" className="btn-secondary" style={{ textDecoration: 'none' }}>
            Cancel
          </Link>
          <button type="submit" className="btn-primary" disabled={saving}>
            {saving ? 'Creating...' : 'Create Incident'}
          </button>
        </div>
      </form>
    </div>
  )
}
