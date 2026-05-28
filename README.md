<div align="center">

# 🪸 Coral Security Command Center
**The Native Coral SQL Threat Intelligence Platform**

![Track](https://img.shields.io/badge/Track-Pirates_of_the_Coral--bean-ff69b4.svg?style=for-the-badge)
![Powered By](https://img.shields.io/badge/Powered_by-Coral_CLI-00f2fe.svg?style=for-the-badge)
[![React](https://img.shields.io/badge/React-18-blue.svg?style=for-the-badge&logo=react)](https://reactjs.org/)
[![Railway](https://img.shields.io/badge/Deployed_on-Railway-0B0D0E.svg?style=for-the-badge&logo=railway)](https://railway.app/)

*Built for the WeMakeDevs "Pirates of the Coral-bean" Hackathon.*
*Zero ETL. Zero Data Warehouse. Zero Glue Code. 100% Native Coral SQL.*

<h3>🔴 <a href="https://coral-production-cd18.up.railway.app">Live Hackathon Demo</a> 🔴</h3>

</div>

---

## 🏴‍☠️ The Architecture: Zero-ETL

Most security platforms require complex ETL pipelines, a heavy data warehouse (Snowflake, BigQuery), and thousands of lines of fragile Python glue code to correlate GitHub pull requests with vulnerability databases and internal Slack chats.

**We threw all of that out.**

By leveraging the **Official Coral CLI**, our Security Command Center performs blazingly fast, native, 4-way SQL `LEFT JOIN`s directly across local API JSON responses. 
We query:
1. **GitHub** (Pull Requests & Commits)
2. **OSV Database** (Vulnerability Intel)
3. **Slack** (Internal Team Chat)
4. **Notion** (Company Security Policies)

...all in a **single Coral SQL query executed locally.** No warehouses. Unprecedented speed. Absolute privacy.

---

## ✨ Features 

*   **Native Coral Engine Integration**: We execute the official `coral.exe` / `coral` binary under the hood. Data is routed via a custom `coral-source.yaml` spec. 
*   **Zero-ETL Architecture**: We fetch raw API data, drop it into local files, and let Coral query it instantly as a relational database. 
*   **Behavioral AI Copilot**: When Coral identifies a threat, our RAG-powered Copilot steps in. It analyzes the developer's historical risk profile, explains the CVE, and generates 1-click Bash rollback scripts.
*   **Dynamic Notion Policy Enforcement**: Security rules dynamically parse via Notion API. If a developer uses a package that violates a Notion policy, Coral's SQL engine flags it instantly.
*   **Award-Winning UI/UX**: A jaw-dropping, premium interface featuring dynamic gradients, glassmorphism, animated tabs, and glowing micro-animations.

---

## 🧠 The Coral SQL Magic

Here is the actual query our Node.js backend passes to the Coral CLI to build our dashboard. Look at the simplicity of joining 4 entirely separate platforms natively:

```sql
SELECT 
  g.pr_id, g.author, g.title, g.package_name, g.merged_at, g.commit_diff,
  o.cve, o.severity, o.cvss,
  s.channel, s.message, s.timestamp,
  n.policy_name, n.policy_rule, n.owner_team, n.description
FROM coral_hackathon.github g
LEFT JOIN coral_hackathon.osv o ON g.package_name = o.package
LEFT JOIN coral_hackathon.slack s ON g.author = s.user
LEFT JOIN coral_hackathon.notion n ON g.package_name = n.applies_to
ORDER BY g.pr_id DESC
```

---

## 🛠️ Auto-Magic Setup & Testing

We wanted to make this the easiest project for judges to evaluate. **You do not need to manually download or configure the Coral CLI.**

Our repository features a smart OS-detection `postinstall` script. Whether you are running on a Windows desktop, a Mac M1, Linux, or deploying on Railway, our script automatically fetches the correct `coral` binary architecture directly from the AWS release bucket, sets executable permissions, and links it to the backend.

### Running Locally in 3 Steps:

1. **Clone & Install:**
   ```bash
   git clone https://github.com/tanmayshukla518-max/Coral.git
   cd Coral
   npm install 
   # ^ This automatically triggers the Coral CLI download!
   ```

2. **Start the Development Servers:**
   ```bash
   # Terminal 1: Start Backend (Port 5000)
   cd backend
   npm run dev

   # Terminal 2: Start Frontend (Port 5173)
   cd frontend
   npm run dev
   ```

3. **Explore the Dashboard:**
   Open `http://localhost:5173`. 
   Navigate to the **Incidents Dashboard** to see Coral SQL output in action.
   Open the **AI Copilot** and ask: *"Explain the critical CVE for stripe"* or *"Give me the rollback procedure for Alice's PR."*

---

## 🔑 Live Data Configuration

The app ships with a rich mock dataset out-of-the-box so judges can immediately test the UI and the Coral SQL execution without configuring tokens. 

To use live API data, go to the **Connections** tab in the UI, enter your tokens, and click **Sync**. The backend will fetch the APIs, update the local JSON files, and the Coral Engine will instantly query the new data!

---

## 🛡️ Built For
**WeMakeDevs Hackathon: Pirates of the Coral-bean (Track 1)**  
*May your queries be fast and your data oceans clear.*
