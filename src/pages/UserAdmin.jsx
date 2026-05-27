import React, { useEffect, useState } from 'react'
import { collection, onSnapshot, doc, updateDoc, orderBy, query } from 'firebase/firestore'
import { db } from '../firebase'
import { useAuth } from '../AuthContext'
import { Link } from 'react-router-dom'

const ROLES = ['admin', 'analyst', 'viewer']

const ROLE_INFO = {
  admin:   { label: 'Admin',   desc: 'Full access — create, edit, delete, manage users', color: '#f85149', bg: 'rgba(248,81,73,0.12)' },
  analyst: { label: 'Analyst', desc: 'Create and edit cases, IOCs, findings. Cannot delete.', color: 'var(--accent)', bg: 'var(--accent-dim)' },
  viewer:  { label: 'Viewer',  desc: 'Read-only access. Cannot create or edit anything.', color: 'var(--text-secondary)', bg: 'var(--bg-elevated)' },
}

function formatDate(ts) {
  if (!ts) return '—'
  const d = ts.toDate ? ts.toDate() : new Date(ts)
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

export default function UserAdmin() {
  const { isAdmin, currentUser } = useAuth()
  const [users, setUsers] = useState([])
  const [saving, setSaving] = useState({})
  const [saved, setSaved] = useState({})

  useEffect(() => {
    const q = query(collection(db, 'users'), orderBy('created_at', 'desc'))
    return onSnapshot(q, snap => {
      setUsers(snap.docs.map(d => ({ uid: d.id, ...d.data() })))
    })
  }, [])

  const handleRoleChange = async (uid, newRole) => {
    setSaving(p => ({ ...p, [uid]: true }))
    try {
      await updateDoc(doc(db, 'users', uid), { role: newRole })
      setSaved(p => ({ ...p, [uid]: true }))
      setTimeout(() => setSaved(p => ({ ...p, [uid]: false })), 2000)
    } finally {
      setSaving(p => ({ ...p, [uid]: false }))
    }
  }

  if (!isAdmin) {
    return (
      <div className="empty-state">
        <span className="empty-state-icon">🔒</span>
        <span className="empty-state-text">Admin access required</span>
        <Link to="/" className="btn-secondary" style={{ textDecoration: 'none', marginTop: 8 }}>Go to Dashboard</Link>
      </div>
    )
  }

  return (
    <div style={{ maxWidth: 860 }}>
      <div className="page-header">
        <div>
          <div className="page-title">User Management</div>
          <div className="page-subtitle">
            Manage analyst roles and access levels — {users.length} registered user{users.length !== 1 ? 's' : ''}
          </div>
        </div>
      </div>

      {/* Role Reference */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 24, flexWrap: 'wrap' }}>
        {ROLES.map(r => (
          <div key={r} className="card" style={{ flex: 1, minWidth: 200, padding: '14px 16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <span style={{
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: 11,
                fontWeight: 600,
                padding: '2px 8px',
                borderRadius: 4,
                background: ROLE_INFO[r].bg,
                color: ROLE_INFO[r].color,
                border: `1px solid ${ROLE_INFO[r].color}33`,
              }}>
                {ROLE_INFO[r].label.toUpperCase()}
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{ROLE_INFO[r].desc}</div>
          </div>
        ))}
      </div>

      {/* Users Table */}
      <div className="table-section">
        <div className="table-section-header">
          <span className="table-section-title">Registered Users</span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            Users are created via Firebase Console → Authentication
          </span>
        </div>
        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Email</th>
                <th>Current Role</th>
                <th>Change Role</th>
                <th>Joined</th>
                <th style={{ width: 80 }}></th>
              </tr>
            </thead>
            <tbody>
              {users.length === 0 ? (
                <tr>
                  <td colSpan={5}>
                    <div className="empty-state">
                      <span className="empty-state-icon">👥</span>
                      <span className="empty-state-text">No users yet — sign in to auto-register</span>
                    </div>
                  </td>
                </tr>
              ) : (
                users.map(u => (
                  <tr key={u.uid} style={{ opacity: saving[u.uid] ? 0.6 : 1 }}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div className="avatar-xs">{(u.email || '?').slice(0, 2).toUpperCase()}</div>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: u.uid === currentUser?.uid ? 'var(--accent)' : 'var(--text-primary)' }}>
                          {u.email || u.uid}
                          {u.uid === currentUser?.uid && (
                            <span style={{ marginLeft: 6, fontSize: 10, color: 'var(--text-muted)' }}>(you)</span>
                          )}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span style={{
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: 11,
                        fontWeight: 600,
                        padding: '2px 8px',
                        borderRadius: 4,
                        background: ROLE_INFO[u.role]?.bg || 'var(--bg-elevated)',
                        color: ROLE_INFO[u.role]?.color || 'var(--text-muted)',
                        border: `1px solid ${ROLE_INFO[u.role]?.color || 'var(--border)'}33`,
                      }}>
                        {(u.role || 'analyst').toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <select
                        className="select-inline"
                        value={u.role || 'analyst'}
                        onChange={e => handleRoleChange(u.uid, e.target.value)}
                        disabled={saving[u.uid] || u.uid === currentUser?.uid}
                        style={{ width: 120 }}
                        title={u.uid === currentUser?.uid ? "You can't change your own role" : ''}
                      >
                        {ROLES.map(r => (
                          <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>
                        ))}
                      </select>
                    </td>
                    <td style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-muted)' }}>
                      {formatDate(u.created_at)}
                    </td>
                    <td>
                      {saving[u.uid] && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Saving...</span>}
                      {saved[u.uid] && !saving[u.uid] && <span style={{ fontSize: 11, color: 'var(--sev-low)' }}>✓ Saved</span>}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card" style={{ marginTop: 16, fontSize: 12, color: 'var(--text-secondary)' }}>
        <strong style={{ color: 'var(--text-primary)' }}>How to add new users:</strong>
        {' '}Go to Firebase Console → Authentication → Users → Add user. They'll appear here automatically on their first sign-in with the default <span className="mitre-pill">analyst</span> role.
      </div>
    </div>
  )
}
