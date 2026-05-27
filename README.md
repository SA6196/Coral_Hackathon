# Coral Security Command Center

> AI-driven cyber defense for hackathon judges: a polished security command center that correlates GitHub, Slack, and vulnerability intelligence in real time.

---

## Why this project wins

Coral is designed to stand out in a security hackathon by combining a strong threat narrative with a clean deployment path.
- Rapid demo readiness using mock data
- Realistic security telemetry from GitHub, Slack, and OSV
- AI investigation guidance plus remediation playbooks
- Separate backend API and React frontend for modern cloud deployment

---

## What it does

- Detects high-risk GitHub activity and secret exposure patterns
- Correlates code changes with Slack conversations and vulnerability feeds
- Produces risk summaries, incident details, and remediation advice
- Supports webhook event simulation for live demo storytelling
- Provides an AI co-pilot for security investigation

---

## Architecture

`	ext
GitHub / Slack / OSV / policy feeds
                   ?
              Coral backend
                   ?
         AI risk analysis engine
                   ?
         React dashboard frontend
`

---

## Tech stack

- Backend: Node.js, Express, dotenv
- Frontend: React, Vite, Axios, Recharts, Framer Motion
- Deployment: Railway for backend, Vercel for frontend

---

## Quick start

### Backend

`ash
cd backend
npm install
npm start
`

Backend API: http://localhost:5000

### Frontend

`ash
cd frontend
npm install
npm run dev
`

Frontend: http://localhost:5173

> The frontend uses VITE_API_URL when set, otherwise it defaults to http://localhost:5000/api.

---

## Environment variables

Create a ackend/.env file with the values you need:

`ash
OPENAI_API_KEY=
GEMINI_API_KEY=
GITHUB_TOKEN=
SLACK_BOT_TOKEN=
NOTION_TOKEN=
FRONTEND_URL=https://your-frontend-domain.com
PUBLIC_URL=https://your-frontend-domain.com
`

> OPENAI_API_KEY enables AI chat features. All other keys are optional for demo mode.

---

## Deployment guide

### Backend (Railway)

1. Import the repo into Railway.
2. Set the service root to ackend.
3. Verify the start command is 
ode src/index.js.
4. Add env vars: FRONTEND_URL, PUBLIC_URL, OPENAI_API_KEY, and any real integration tokens.

### Frontend (Vercel)

1. Import the repo into Vercel.
2. Set the project root to rontend.
3. Build command: 
pm run build
4. Output directory: dist
5. Set VITE_API_URL=https://<backend-url>/api

---

## Demo flow

- Use the initial mock data to show a threat scenario immediately.
- Open the dashboard and highlight the incident correlation panels.
- Trigger the Webhook Sandbox to simulate a GitHub event.
- Show the AI co-pilot explaining remediation steps.

---

## Project structure

`	ext
backend/        # Express API and security engine
frontend/       # Vite React dashboard
Coral_queries/  # Coral query examples
demo_flow/      # demo sequence and storytelling notes
docs/           # supporting docs and mock responses
README.md       # project overview and setup
`

---

## Notes for winning

- Start the pitch with a security incident story.
- Demonstrate fast mock-data onboarding first.
- Highlight that this is deployable and cloud-ready.
- Close with the AI guidance + remediation workflow.

---

## Need extra help?

I can also add:
- a deploy.md with one-click instructions
- GitHub Actions deployment automation
- a fallback single-host backend + frontend bundle
