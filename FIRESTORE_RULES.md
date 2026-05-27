# Firestore Security Rules

Paste these into Firebase Console → Firestore → Rules tab:

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    // ── Helper functions ──────────────────────────────────────
    function isLoggedIn() {
      return request.auth != null;
    }
    function userRole() {
      return get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role;
    }
    function isAdmin() {
      return isLoggedIn() && userRole() == 'admin';
    }
    function isAnalystOrAdmin() {
      return isLoggedIn() && (userRole() == 'analyst' || userRole() == 'admin');
    }

    // ── cases, iocs, findings, commands, tools ─────────────────
    // Anyone can read. Only analysts/admins can write. Only admins can delete.
    match /cases/{docId} {
      allow read: if true;
      allow create, update: if isAnalystOrAdmin();
      allow delete: if isAdmin();
    }
    match /iocs/{docId} {
      allow read: if true;
      allow create, update: if isAnalystOrAdmin();
      allow delete: if isAdmin();
    }
    match /findings/{docId} {
      allow read: if true;
      allow create, update: if isAnalystOrAdmin();
      allow delete: if isAdmin();
    }
    match /commands/{docId} {
      allow read: if true;
      allow create, update: if isAnalystOrAdmin();
      allow delete: if isAdmin();
    }
    match /tools/{docId} {
      allow read: if true;
      allow create, update: if isAnalystOrAdmin();
      allow delete: if isAdmin();
    }

    // ── users (role profiles) ──────────────────────────────────
    // Any logged-in user can read/write their own profile.
    // Only admins can read/update OTHER users' profiles.
    match /users/{userId} {
      allow read: if isLoggedIn() && (request.auth.uid == userId || isAdmin());
      allow create: if isLoggedIn() && request.auth.uid == userId;
      allow update: if isLoggedIn() && (request.auth.uid == userId || isAdmin());
      allow delete: if isAdmin();
    }
  }
}
```
