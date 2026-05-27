import React, { createContext, useContext, useEffect, useState } from 'react'
import { onAuthStateChanged } from 'firebase/auth'
import { doc, getDoc, setDoc, serverTimestamp } from 'firebase/firestore'
import { auth, db } from './firebase'

// ─── ROLES ───────────────────────────────────────────────────────────────
// admin   → full access: create, edit, delete, manage users
// analyst → create + edit (no delete of cases)
// viewer  → read-only (same as unauthenticated guest but has an account)
// guest   → unauthenticated, read-only (Firestore public read rules)

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [currentUser, setCurrentUser] = useState(undefined)
  const [role, setRole] = useState(null)
  const [roleLoading, setRoleLoading] = useState(false)

  useEffect(() => {
    const unsub = onAuthStateChanged(auth, async (user) => {
      setCurrentUser(user)
      if (user) {
        setRoleLoading(true)
        try {
          const userDoc = await getDoc(doc(db, 'users', user.uid))
          if (userDoc.exists()) {
            setRole(userDoc.data().role || 'analyst')
          } else {
            // First-time user — auto-assign 'analyst' role and create their profile
            await setDoc(doc(db, 'users', user.uid), {
              email: user.email,
              role: 'analyst',
              created_at: serverTimestamp(),
            })
            setRole('analyst')
          }
        } catch {
          setRole('analyst') // fallback
        } finally {
          setRoleLoading(false)
        }
      } else {
        setRole(null)
        setRoleLoading(false)
      }
    })
    return unsub
  }, [])

  const loading = currentUser === undefined || roleLoading

  // Convenience booleans
  const isAdmin   = role === 'admin'
  const isAnalyst = role === 'admin' || role === 'analyst'  // analysts + admins can edit
  const isViewer  = role === 'viewer'
  const isGuest   = !currentUser

  // canDelete: only admins can delete cases (analysts cannot)
  const canDelete = role === 'admin'
  // canEdit: analysts and admins can create/edit
  const canEdit   = role === 'admin' || role === 'analyst'

  return (
    <AuthContext.Provider value={{
      currentUser,
      role,
      loading,
      isAdmin,
      isAnalyst,
      isViewer,
      isGuest,
      canDelete,
      canEdit,
    }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
