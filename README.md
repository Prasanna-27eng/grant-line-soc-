# ⚓ Grand Line SOC Dashboard

A production-grade **Security Operations Centre (SOC) Analyst Dashboard** built with React 18, Firebase, and AI-powered features. Designed for real-world incident management, threat hunting, and security analytics — inspired by professional SOC tools like CrowdStrike Falcon and Splunk SIEM.

![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=white)
![Firebase](https://img.shields.io/badge/Firebase-10-FFCA28?logo=firebase&logoColor=black)
![Vite](https://img.shields.io/badge/Vite-5-646CFF?logo=vite&logoColor=white)
![Netlify](https://img.shields.io/badge/Deployed-Netlify-00C7B7?logo=netlify&logoColor=white)

---

## 📸 Overview

Grand Line SOC is a full-stack web application that enables security analysts to:

- Manage and investigate security incidents end-to-end
- Track Indicators of Compromise (IOCs) with live VirusTotal enrichment
- Map incidents to the MITRE ATT&CK framework
- Generate AI-powered case summaries and threat intelligence
- Export professional PDF incident reports
- Collaborate with role-based access control (Admin / Analyst / Viewer)

---

## ✨ Features

### 🗂️ Incident Management
- Create, view, update, and close security cases
- Severity levels: Critical, High, Medium, Low
- Case statuses: Open, Investigating, Contained, Closed
- Full-text search and multi-filter incident queue
- Assign lead analysts to cases

### 🔍 MITRE ATT&CK Mapping
- Tag cases with official MITRE ATT&CK tactics (all 14 tactics)
- Add specific technique IDs (e.g. T1059.001)
- Visual tactic pills on case cards and detail views
- Filter findings by tactic across the Intelligence Archive

### 🦠 IOC Management & VirusTotal Enrichment
- Log IOCs by type: IP address, domain, file hash, URL
- One-click VirusTotal API v3 enrichment per IOC
- Live verdict badges: Malicious / Suspicious / Clean / Scanning
- Detailed engine counts (malicious / suspicious / total)

### 🤖 AI-Powered Features (Groq — free tier)
| Feature | Description |
|---|---|
| **AI Case Summarizer** | Generates executive incident summaries from case data, IOCs, findings, and commands |
| **IOC Context Explainer** | Explains any IOC with threat intel context, known campaigns, and recommended actions |
| **Smart Severity Suggester** | Analyses case title + description and suggests severity + MITRE tactics automatically |

### 📊 Analytics Dashboard
- Live stat row: active alerts, IOC count, detection rate
- Stacked bar chart (P1/P2 incidents by month) via Recharts
- Security Pulse segmented bars by category
- Live incident queue with severity indicators

### 📄 PDF Report Export
- 5-page dark-themed professional incident report
- Covers: case summary, IOCs table, findings, commands, timeline
- One-click export from any case detail page

### 👥 Role-Based Access Control
| Role | Permissions |
|---|---|
| **Admin** | Full access — create, edit, delete cases + manage all users |
| **Analyst** | Create and edit cases, IOCs, findings, commands |
| **Viewer** | Read-only access to all data |
| **Guest** | Public read-only (no login required) |

### 🕐 Timeline View
- Visual vertical timeline per case
- Events: case opened → findings → case closed
- Color-coded by severity

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18 + Vite 5 |
| Routing | React Router v6 (HashRouter) |
| Backend / DB | Firebase Firestore v10 |
| Auth | Firebase Authentication |
| Charts | Recharts |
| PDF Export | jsPDF + jspdf-autotable |
| AI / LLM | Groq API (llama-3.3-70b-versatile) |
| Threat Intel | VirusTotal API v3 |
| Styling | Plain CSS with CSS Variables (dark theme) |
| Deployment | Netlify |

---

## 📁 Project Structure

```
soc-firebase-dashboard/
├── index.html
├── vite.config.js
├── package.json
├── .env                        # API keys (not committed)
├── .gitignore
├── FIRESTORE_RULES.md          # Firestore security rules to paste into Firebase Console
└── src/
    ├── main.jsx
    ├── App.jsx                 # Router + sidebar + auth shell
    ├── AuthContext.jsx         # Role-based auth context
    ├── firebase.js             # Firebase initialisation
    ├── aiUtils.js              # Groq AI utility functions
    ├── styles/
    │   └── global.css          # Full CSS variable design system
    └── pages/
        ├── Login.jsx           # Firebase email/password auth
        ├── Dashboard.jsx       # Analytics + live stats
        ├── Cases.jsx           # Incident queue + filters
        ├── NewCase.jsx         # Create case form + AI suggest
        ├── CaseDetail.jsx      # Full case detail (IOCs, Findings, Commands, Tools)
        ├── Findings.jsx        # Intelligence Archive
        ├── Timeline.jsx        # Visual case timeline
        └── UserAdmin.jsx       # Admin user management
```

---

## 🚀 Getting Started

### Prerequisites
- Node.js 18+
- A Firebase project (free Spark plan works)
- A Groq API key (free at [console.groq.com](https://console.groq.com))
- A VirusTotal API key (free at [virustotal.com](https://www.virustotal.com))

### 1. Clone the repository
```bash
git clone https://github.com/Prasanna-27eng/grant-line-soc-.git
cd grant-line-soc-
```

### 2. Install dependencies
```bash
npm install
```

### 3. Set up environment variables

Create a `.env` file in the project root:

```env
VITE_GROQ_API_KEY=your_groq_api_key_here
VITE_VT_API_KEY=your_virustotal_api_key_here
VITE_FIREBASE_API_KEY=your_firebase_api_key
VITE_FIREBASE_AUTH_DOMAIN=your_project.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=your_project_id
VITE_FIREBASE_STORAGE_BUCKET=your_project.firebasestorage.app
VITE_FIREBASE_MESSAGING_SENDER_ID=your_sender_id
VITE_FIREBASE_APP_ID=your_app_id
```

### 4. Set up Firebase

1. Create a project at [console.firebase.google.com](https://console.firebase.google.com)
2. Enable **Authentication** → Email/Password sign-in
3. Enable **Firestore Database**
4. Paste the security rules from `FIRESTORE_RULES.md` into Firestore → Rules tab
5. Copy your Firebase config values into `.env`

### 5. Set yourself as Admin

New accounts default to `analyst` role. To become admin:

1. Sign up / sign in to the app
2. Go to Firebase Console → Firestore → `users` collection
3. Find your document (named with your UID from Authentication tab)
4. Change the `role` field value to `"admin"`

### 6. Run locally
```bash
npm run dev
```

Open [http://localhost:5173](http://localhost:5173)

### 7. Build for production
```bash
npm run build
```

The `dist/` folder is ready to deploy to Netlify, Vercel, or any static host.

---

## ☁️ Deploying to Netlify

### Option A — Drag and Drop
1. Run `npm run build`
2. Drag the `dist/` folder to [app.netlify.com/drop](https://app.netlify.com/drop)

### Option B — GitHub Auto-Deploy
1. Connect your GitHub repo to Netlify
2. Set build command: `npm run build`
3. Set publish directory: `dist`
4. Add all `VITE_*` environment variables in **Site configuration → Environment variables**
5. Every push to `main` triggers an automatic redeploy

---

## 🔐 Firestore Security Rules

The app uses role-based Firestore rules. Paste the contents of `FIRESTORE_RULES.md` into your Firebase Console → Firestore → Rules tab.

Summary of access:
- **Public (unauthenticated)**: Read-only on cases, IOCs, findings, commands, tools
- **Analyst / Admin**: Create and update all collections
- **Admin only**: Delete documents, manage other users' roles

---

## 🗄️ Firestore Collections

| Collection | Purpose |
|---|---|
| `cases` | Incident records (title, severity, status, MITRE tactics) |
| `iocs` | Indicators of Compromise with optional VT enrichment |
| `findings` | Intelligence findings linked to cases |
| `commands` | Commands run during investigation |
| `tools` | Tools used during investigation |
| `users` | User profiles with role assignments |

---

## 🔑 API Keys

| Service | Where to get it | Free tier |
|---|---|---|
| [Groq](https://console.groq.com) | console.groq.com → API Keys | Yes — generous free tier |
| [VirusTotal](https://www.virustotal.com/gui/join-us) | virustotal.com → Sign up | Yes — 500 requests/day |
| [Firebase](https://console.firebase.google.com) | Firebase Console → Project settings | Yes — Spark plan |

> ⚠️ **Never commit your `.env` file.** It is included in `.gitignore` by default. Add your environment variables directly in Netlify's dashboard for production deployments.

---

## 🗺️ Roadmap / Future Features

- [ ] Slack / Teams alert notifications
- [ ] Automated IOC correlation across cases
- [ ] STIX/TAXII threat feed ingestion
- [ ] Playbook/runbook attachment per case
- [ ] Real-time multi-analyst collaboration
- [ ] Dark/light theme toggle
- [ ] Mobile-responsive layout
- [ ] SOAR-style automated response actions
- [ ] Custom dashboard widgets
- [ ] Export to STIX 2.1 format

---

## 👤 Author

**Prasanna Kumar**
- GitHub: [@Prasanna-27eng](https://github.com/Prasanna-27eng)

---

## 📄 License

This project is private and intended for personal/educational use.

---

*Built with ⚓ by the Grand Line SOC team*
