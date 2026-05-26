# 🛡️ Coral Security Command Center

AI-powered enterprise cybersecurity monitoring platform built during the Coral Hackathon.

Coral Security Command Center continuously monitors GitHub activity, Slack discussions, and vulnerability intelligence feeds to detect, correlate, and explain security threats in real time.

---

# 🚀 Features

- 🔍 GitHub commit monitoring
- 💬 Slack security discussion analysis
- 🧠 AI-powered risk summarization
- ⚠️ CVE / OSV vulnerability correlation
- 📊 Enterprise security dashboard
- 🚨 Critical incident detection
- 📈 Risk scoring engine
- 🛠️ Remediation recommendations

---

# 🧠 Problem Statement

Modern companies use:
- GitHub for source code
- Slack for communication
- Open-source dependencies

Security teams cannot manually monitor:
- secret leaks
- risky package updates
- vulnerability disclosures
- suspicious internal discussions

Our system acts as an AI-powered cybersecurity analyst that automatically correlates security signals across multiple platforms.

---

# 🏗️ Architecture

```text
GitHub → Security Events
Slack → Internal Discussions
OSV → Vulnerability Intelligence
           ↓
        Coral Engine
           ↓
    AI Risk Correlation
           ↓
 Enterprise Security Dashboard
```

---

# ⚡ Tech Stack

## Frontend
- React
- Vite
- TailwindCSS

## Backend
- Node.js
- Express.js

## AI / Security
- Coral
- CVE / OSV Intelligence
- Risk Analysis Engine

---

# 📂 Project Structure

```text
Coral_Hackathon/
│
├── frontend/
├── backend/
├── Coral_queries/
├── demo_flow/
├── docs/
└── README.md
```

---

# 🧪 Demo Scenario

### Simulated Incident Flow

1. Developer exposes production API key
2. Slack discussion reports suspicious behavior
3. OSV detects critical vulnerability
4. Coral correlates all events
5. Dashboard raises critical security alert
6. AI recommends remediation action

---

# 📸 Screenshots

_Add dashboard screenshots here_

---

# ⚙️ Local Setup

## Backend

```bash
cd backend
npm install
npm start
```

Runs on:
```text
http://localhost:5000
```

---

## Frontend

```bash
cd frontend
npm install
npm run dev
```

Runs on:
```text
http://localhost:5173
```

---

# 👥 Team Members

- Member 1 — Coral & Backend Lead
- Member 2 — AI/LLM Engineer
- Member 3 — Frontend Engineer
- Member 4 — DevOps & Demo Engineer

---

# 🏆 Vision

Our goal is to build an intelligent enterprise security monitoring platform capable of proactively identifying and explaining cyber threats before they become production incidents.

---