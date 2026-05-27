import React from 'react'
import { HashRouter, Routes, Route, NavLink, useNavigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './AuthContext'
import { auth } from './firebase'
import { signOut } from 'firebase/auth'

import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Cases from './pages/Cases'
import NewCase from './pages/NewCase'
import CaseDetail from './pages/CaseDetail'
import Findings from './pages/Findings'
import Timeline from './pages/Timeline'
import UserAdmin from './pages/UserAdmin'

function Sidebar() {
  const { canEdit, isAdmin, currentUser } = useAuth()
  const navigate = useNavigate()

  const initials = currentUser?.email
    ? currentUser.email.slice(0, 2).toUpperCase()
    : '?'

  const handleLogout = async () => {
    await signOut(auth)
    navigate('/')
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-logo" title="Grand Line SOC">
        <span className="sidebar-anchor">⚓</span>
      </div>

      <nav className="sidebar-nav">
        <NavLink to="/" end title="Dashboard" className={({ isActive }) => 'sidebar-btn' + (isActive ? ' active' : '')}>
          ⊞
        </NavLink>
        <NavLink to="/cases" title="Incident Queue" className={({ isActive }) => 'sidebar-btn' + (isActive ? ' active' : '')}>
          ◈
        </NavLink>
        <NavLink to="/findings" title="Intelligence Archive" className={({ isActive }) => 'sidebar-btn' + (isActive ? ' active' : '')}>
          ◉
        </NavLink>
        <NavLink to="/timeline" title="Attack Timeline" className={({ isActive }) => 'sidebar-btn' + (isActive ? ' active' : '')}>
          ◷
        </NavLink>
        {canEdit && (
          <NavLink to="/cases/new" title="New Incident" className={({ isActive }) => 'sidebar-btn' + (isActive ? ' active' : '')}>
            ＋
          </NavLink>
        )}
        {isAdmin && (
          <NavLink to="/admin/users" title="User Management" className={({ isActive }) => 'sidebar-btn' + (isActive ? ' active' : '')}>
            👥
          </NavLink>
        )}
      </nav>

      <div className="sidebar-bottom">
        {currentUser ? (
          <>
            <div className="avatar-circle" title={currentUser?.email}>{initials}</div>
            <button className="sidebar-btn sidebar-logout" title="Sign Out" onClick={handleLogout}>
              ⏻
            </button>
          </>
        ) : (
          <NavLink to="/login" title="Sign In" className="sidebar-btn">
            ↗
          </NavLink>
        )}
      </div>
    </aside>
  )
}

function RoleBadge({ role }) {
  const config = {
    admin:   { label: 'ADMIN',   style: { background: 'rgba(248,81,73,0.15)', color: '#f85149', border: '1px solid rgba(248,81,73,0.4)' } },
    analyst: { label: 'ANALYST', style: { background: 'var(--accent-dim)', color: 'var(--accent)', border: '1px solid var(--accent-border)' } },
    viewer:  { label: 'VIEWER',  style: { background: 'var(--bg-elevated)', color: 'var(--text-secondary)', border: '1px solid var(--border)' } },
  }
  const c = config[role]
  if (!c) return null
  return (
    <span style={{
      fontFamily: 'JetBrains Mono, monospace',
      fontSize: 10,
      fontWeight: 600,
      borderRadius: 4,
      padding: '2px 8px',
      letterSpacing: '0.08em',
      ...c.style,
    }}>
      {c.label}
    </span>
  )
}

function Header() {
  const { currentUser, role, isGuest } = useAuth()

  return (
    <header className="topbar">
      <div className="topbar-left">
        <span className="topbar-brand">Grand Line SOC</span>
        <input
          className="topbar-search"
          type="text"
          placeholder="Find threat data..."
          readOnly
        />
      </div>
      <div className="topbar-right">
        <span className="topbar-icon" title="Notifications">🔔</span>
        <span className="topbar-icon" title="Settings">⚙</span>
        {isGuest ? (
          <span className="topbar-guest-label">GUEST</span>
        ) : (
          <>
            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              {currentUser?.email?.split('@')[0]}
            </span>
            <RoleBadge role={role} />
          </>
        )}
      </div>
    </header>
  )
}

function AppShell() {
  const { loading } = useAuth()

  if (loading) {
    return (
      <div className="loading-screen">
        <span className="loading-icon">⚓</span>
        <span className="loading-text">Grand Line SOC</span>
      </div>
    )
  }

  return (
    <div className="app-shell">
      <Sidebar />
      <div className="main-area">
        <Header />
        <main className="content-area">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/login" element={<Login />} />
            <Route path="/cases" element={<Cases />} />
            <Route path="/cases/new" element={<NewCase />} />
            <Route path="/cases/:id" element={<CaseDetail />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/timeline" element={<Timeline />} />
            <Route path="/admin/users" element={<UserAdmin />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <HashRouter>
      <AuthProvider>
        <AppShell />
      </AuthProvider>
    </HashRouter>
  )
}
