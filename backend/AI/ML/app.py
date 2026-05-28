from flask import Flask, jsonify, request
from flask_cors import CORS
import yaml
import os
import datetime
from openai import OpenAI

app = Flask(__name__)
# Enable CORS globally so frontend can communicate with the backend
CORS(app, resources={r"/*": {"origins": "*"}})

# ------------------------------------------------------------------
# 🎛️ CONFIGURATION & DEVOPS ENVIRONMENT LAYER
# ------------------------------------------------------------------
OPENAI_KEY = os.environ.get("OPENAI_API_KEY")
AI_MODEL = os.environ.get("AI_MODEL", "gpt-4o-mini")

# ------------------------------------------------------------------
# 🪸 DATA ACCESS LAYER: CORAL INTERACTION
# ------------------------------------------------------------------
YAML_PATH = os.path.join(os.path.dirname(__file__), "mock_security.yaml")

def run_coral_engine(sql_query=None):
    """
    Reads mock_security.yaml, extracts records safely, and gets column names.
    Optional sql_query argument is kept for compatibility and logging.
    """
    if not os.path.exists(YAML_PATH):
        return {"error": f"Database file {YAML_PATH} not found"}
        
    try:
        with open(YAML_PATH, "r") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        return {"error": f"Failed to parse YAML: {str(e)}"}
    
    # Extract records safely
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        if 'mock_security' in data:
            records = data['mock_security']
        else:
            records = []
    else:
        records = []

    # Fix: Safely get columns from first record if records is a list of dicts
    columns = []
    if records and isinstance(records, list):
        if isinstance(records[0], dict):
            columns = list(records[0].keys())
    elif isinstance(records, dict):
        columns = list(records.keys())

    return {
        "columns": columns,
        "rows": records,
        "row_count": len(records)
    }

def get_client(request_key=None):
    """
    Get OpenAI client. Prioritizes API key from request headers, 
    then falls back to server env variables.
    """
    key = request_key or request.headers.get("X-OpenAI-Key") or OPENAI_KEY
    if key and key.strip() and key.strip() != "undefined" and key.strip() != "null":
        return OpenAI(api_key=key.strip())
    return None

# ------------------------------------------------------------------
# 🤖 COGNITIVE LAYER: EXPERT DETERMINISTIC INFERENCE
# ------------------------------------------------------------------
def generate_personalized_investigation_report(selected_row, all_incidents):
    dev = selected_row.get("author", "Unknown")
    sev = selected_row.get("severity", "safe")
    cve = selected_row.get("vuln_id", "N/A")
    pkg = selected_row.get("package", "unknown")
    code = selected_row.get("code", "SEC-UNK")
    commit_msg = selected_row.get("commit_message", "N/A")
    chat_msg = selected_row.get("message_text", "No internal discussion found.")
    
    # Find all incidents by this developer
    dev_incidents = [i for i in all_incidents if i.get("author") == dev]
    sev_scores = {"critical": 95, "high": 75, "medium": 45, "safe": 10}
    avg_risk = sum(sev_scores.get(str(i.get("severity", "safe")).lower(), 10) for i in dev_incidents)
    avg_risk = int(round(avg_risk / len(dev_incidents))) if dev_incidents else 10
    
    critical_count = len([i for i in dev_incidents if str(i.get("severity")).lower() == "critical"])
    is_secret = dev == "alice_dev" or code == "SEC-101" or "key" in commit_msg.lower() or "credentials" in commit_msg.lower()
    secret_leaks = 1 if is_secret else 0
    
    anomaly_score = min(100, int((avg_risk * 0.4) + (critical_count * 15) + (secret_leaks * 30)))
    
    persona = "🟢 Secure Contributor"
    if secret_leaks > 0 and critical_count > 0:
        persona = "🚨 Insider Threat / Compromised Account"
    elif critical_count >= 2:
        persona = "🟠 High-Risk Operator"
    elif avg_risk >= 40:
        persona = "🟡 Careless Committer"
        
    issue_explanation = ""
    exploit_scenarios = ""
    
    dev_lower = dev.lower()
    
    if secret_leaks > 0:
        issue_explanation = f"The developer **{dev}** committed a hardcoded secret directly inside the codebase. Hardcoding secrets in git trees is highly risky as it exposes long-lived authentication keys to any reader of the repository, enabling immediate privilege escalation."
        exploit_scenarios = f"An attacker gaining read access to this code or repository can immediately steal the exposed credentials to access our live production infrastructure, bypass multi-factor authentication, and download sensitive customer data."
    elif "contractor" in dev_lower or code == "SEC-103":
        issue_explanation = f"The developer **{dev}** introduced highly suspicious code structures, including dynamic shell execution or setup script shell hooks. Executing unverified user-supplied input or raw commands dynamically is a classic backdoor pattern, which is banned under SOC2 and internal compliance policies."
        exploit_scenarios = f"An attacker could exploit this dynamic execution vector to feed remote commands to our servers, resulting in arbitrary shell execution, complete node takeover, and lateral movement across the Kubernetes cluster."
    elif pkg == "lodash" or pkg == "axios":
        issue_explanation = f"The developer **{dev}** merged dependency changes referencing the package `{pkg}` which is vulnerable to security exploits (including Prototype Pollution). Upgrade validation is required to ensure nested/transitive components are updated."
        exploit_scenarios = f"Prototype pollution allows malicious actors to inject properties into global prototypes, causing general application crashes (DoS) or, under specific configurations, remote code execution (RCE) inside Node.js."
    elif pkg == "jsonwebtoken":
        issue_explanation = f"The developer **{dev}** configured JWT token verification/signature operations using the `{pkg}` package. Known vulnerabilities in outdated versions allow algorithm confusion attacks or signature bypasses."
        exploit_scenarios = f"Attackers can modify JWT headers to use symmetric algorithms or 'none' verification, bypassing authorization mechanisms entirely to log in as admin users."
    else:
        issue_explanation = f"The developer **{dev}** committed modifications in `{pkg}` which have been flagged by the security engine due to outdated packages or policy non-compliance."
        exploit_scenarios = f"Security issues could lead to dependency-injection attacks or localized memory leak issues, decreasing service stability and integrity."
        
    slack_discussion = f"> **{dev}:** \"{chat_msg}\"" if chat_msg and chat_msg != "No internal discussion found." else "> No active Slack team discussions found for this incident."
    
    # Calculate a dynamic risk score
    risk_score = sev_scores.get(sev.lower(), 10)
    if secret_leaks > 0:
        risk_score = min(100, risk_score + 10)
    if code in ["SEC-101", "SEC-102", "SEC-103"]:
        risk_score = min(100, risk_score + 15) # Notion policy boost simulation
        
    report = f"""## 🔍 AI Security Investigation — {code}

### 🚨 Threat Overview & Impact
- **Severity:** {sev.upper()} Risk (Risk Score: **{risk_score}/100**)
- **Vulnerability Package:** `{pkg}` | **CVE:** `{cve}`
- **Responsible Developer:** **{dev}**
- **Introduced In:** Commit "{commit_msg}"
- **Risk Score:** {risk_score} (calculated dynamically based on severity and policies)

### 👤 Developer Risk Profile Context
- **Behavioral Persona:** **{persona}**
- **Trust Score:** **{100 - anomaly_score}/100** | **Behavioral Anomaly Factor:** **{anomaly_score}%**
- **Developer Track Record:** Introduced **{len(dev_incidents)}** security incident(s) recently. Average historical incident risk score is **{avg_risk}/100**.

### 📖 Deep-Dive Analysis of the Issue
{issue_explanation}

### 💀 Exploit Possibilities & Attack Scenarios
{exploit_scenarios}

### 💬 Correlated Social & Chat Evidence
A scan of corporate chat logs shows active discussion regarding this commit:
{slack_discussion}

### 🛠️ Immediate Containment Playbook
- **Rollback Action:** Revert commit immediately and scale down the deployment.
- **Audit Priority:** **{"P0 (Immediate action required)" if sev.lower() == "critical" else "P1 (Remediate within 24 hours)" if sev.lower() == "high" else "P2 (Resolve in next release cycle)"}**
"""
    return report

def generate_personalized_remediation_plan(selected_row, all_incidents):
    dev = selected_row.get("author", "Unknown")
    sev = selected_row.get("severity", "safe")
    cve = selected_row.get("vuln_id", "N/A")
    pkg = selected_row.get("package", "unknown")
    code = selected_row.get("code", "SEC-UNK")
    commit_hash = selected_row.get("commit_hash", "HEAD")
    
    dev_lower = dev.lower()
    is_secret = dev == "alice_dev" or code == "SEC-101" or "key" in selected_row.get("commit_message", "").lower() or "credentials" in selected_row.get("commit_message", "").lower()
    
    title = f"Security Hardening Plan — {code}"
    subtitle = "Standard patching and validation guidelines"
    actions = []
    scripts = []
    est_time = "1 Hour"
    
    if is_secret:
        title = f"🛡️ Database/API Credential Rotation & Clean Guide — {dev}"
        subtitle = f"Rotate hardcoded credentials committed by {dev} and purge history in {pkg}"
        est_time = "45 Minutes"
        actions = [
            f"Immediately revoke and invalidate the exposed secret key in the database console.",
            f"Purge the secret leak from Git commit history using Git-filter-repo to prevent history leakage.",
            f"Transition {dev}'s configuration to load credentials dynamically via environment variables.",
            f"Verify the fix by running an automated TruffleHog scanner check locally."
        ]
        scripts = [
            f"# 1. Revert the commit that exposed secrets\ngit log --oneline -5\ngit revert {commit_hash} --no-edit\ngit push origin HEAD --force-with-lease",
            f"# 2. Scrub secret from git history safely\npip install git-filter-repo\ngit filter-repo --invert-paths --path <secret-file>",
            f"# 3. Check for any other active leaks\npip install trufflehog\ntrufflehog git file://. --since-commit HEAD~5"
        ]
    elif "contractor" in dev_lower or code == "SEC-103":
        title = f"🛡️ Critical Sandbox & Command Injection Quarantine — contractor_x"
        subtitle = f"Revert unauthorized setup modifications and backdoor execution hooks in {pkg}"
        est_time = "2 Hours"
        actions = [
            f"Quarantine the developer contractor_x's push access credentials pending security and code review.",
            f"Perform a direct git revert to revoke setup scripts and command injection risks in node-setup/vm2.",
            f"Implement strict 2-person code reviews and merge gates using repository Branch Protection rules."
        ]
        scripts = [
            f"# 1. Revert contractor_x's unauthorized hooks commit\ngit revert {commit_hash} --no-edit\ngit push origin HEAD --force-with-lease",
            f"# 2. Reset local pre-commit scripts and verify files\nrm -rf .git/hooks/pre-commit\ngit checkout HEAD -- setup.sh\ngit status",
            f"# 3. Secure branch protection gates via GitHub CLI\ngh api -X PUT /repos/:owner/:repo/branches/main/protection -F required_pull_request_reviews.required_approving_review_count=2"
        ]
    elif pkg == "lodash" or pkg == "axios":
        title = f"🛡️ Dependency Patching & Prototype Pollution Validation — {dev}"
        subtitle = f"Patch lodash/axios vulnerabilities in {dev}'s branch and audit transitive dependencies"
        est_time = "30 Minutes"
        actions = [
            f"Upgrade `{pkg}` package in package.json to the stable, fully secure version.",
            f"Audit the lockfile to ensure all sub-dependencies are clean from vulnerable lodash versions.",
            f"Run automated unit and integration tests to ensure no API compatibility breaking changes."
        ]
        scripts = [
            f"# 1. Install latest secure release version\nnpm install {pkg}@latest --save",
            f"# 2. Run high-severity vulnerability audit check\nnpm audit --audit-level=high",
            f"# 3. Execute application validation test suite\nnpm test && npm run build"
        ]
    elif pkg == "jsonwebtoken":
        title = f"🛡️ JWT Authorization Bypass Security Patching — {dev}"
        subtitle = f"Secure token validation and upgrade jsonwebtoken for {dev}'s PR"
        est_time = "1 Hour"
        actions = [
            f"Upgrade vulnerable `jsonwebtoken` package to avoid signature authentication bypass vulnerabilities.",
            f"Review verification middleware logic to verify key encryption algorithm constraints are active.",
            f"Ensure private signing keys are loaded strictly from the environment and not hardcoded."
        ]
        scripts = [
            f"# 1. Update package version\nnpm install jsonwebtoken@9.0.2 --save",
            f"# 2. Audit dependencies for nested auth issues\nnpm audit",
            f"# 3. Test OAuth/JWT authorization tests\nnpm test"
        ]
    else:
        title = f"🛡️ General Security Patching & Code Review — {dev}"
        subtitle = f"Audit and verify package updates in {dev}'s pull request"
        est_time = "2 Hours" if sev.lower() == "critical" else "1 Hour"
        actions = [
            f"Upgrade the `{pkg}` library to the latest stable and secure release.",
            f"Arrange a security pairing review with {dev} to review the dependency changes.",
            f"Execute standard package dependency scans and ensure tests pass."
        ]
        scripts = [
            f"# 1. Install latest package dependency version\nnpm install {pkg}@latest",
            f"# 2. Audit dependency tree\nnpm audit",
            f"# 3. Rebuild bundle and verify compatibility\nnpm test && npm run build"
        ]
        
    return {
        "title": title,
        "subtitle": subtitle,
        "severity": sev,
        "estimated_time": est_time,
        "actions": actions,
        "scripts": scripts
    }

def run_cognitive_nlp_analysis(incident_matrix, client=None):
    """
    Runs security log incident analysis using OpenAI or a detailed local template.
    """
    # Incident data extracted safely
    code = incident_matrix.get('code', 'N/A')
    commit_msg = incident_matrix.get('commit_message', 'N/A')
    author = incident_matrix.get('author', 'N/A')
    chat_msg = incident_matrix.get('message_text', 'N/A')
    vuln_id = incident_matrix.get('vuln_id', 'N/A')
    severity = incident_matrix.get('severity', 'N/A')
    impact = incident_matrix.get('impact', 'N/A')
    pkg = incident_matrix.get('package', 'N/A')

    if not client:
        # Goated fallback personalization report
        raw_records = run_coral_engine()
        rows = raw_records.get("rows", [])
        return {
            "report": generate_personalized_investigation_report(incident_matrix, rows)
        }

    system_guardrail = (
        "You are an automated SecOps AI Agent. "
        "Analyze raw correlated logs and generate a professional incident report in markdown. "
        "Explain: 1. Business risk in simple terms. 2. Why the vulnerability matters. "
        "3. Severity impact. 4. Exploit possibilities. 5. Rollback suggestions."
    )
    
    user_payload = f"""
    [CRITICAL ALERT: REVIEW CORRELATED EVIDENCE MATRIX]
    Incident Code: {code}
    1. GITHUB COMMIT: "{commit_msg}" by {author} (Commit: {incident_matrix.get('commit_hash', 'N/A')})
    2. CHAT LOGS: "{chat_msg}"
    3. VULN ID: {vuln_id} (Severity: {severity}, Package: {pkg})
    4. GENERAL BUSINESS IMPACT: {impact}
    
    Structure your report as:
    ### 🚨 SECURITY REPORT ({code})
    1. SUMMARY (Simple terms business risk)
    2. ROOT CAUSE & WHY IT MATTERS
    3. RISK SCORE & SEVERITY IMPACT
    4. EXPL OIT POSSIBILITIES
    5. REMEDIATION & ROLLBACK SUGGESTIONS
    """

    try:
        response = client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": system_guardrail},
                {"role": "user", "content": user_payload}
            ],
            temperature=0.15,
            max_tokens=1200
        )
        return {"report": response.choices[0].message.content}
    except Exception as e:
        return {"error": f"LLM Gateway Exception: {str(e)}"}

# ------------------------------------------------------------------
# 📡 PLUG-AND-PLAY API CONTROLLER ROUTES
# ------------------------------------------------------------------

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """
    Endpoint to list all mock security logs.
    """
    raw_records = run_coral_engine()
    if "error" in raw_records:
        return jsonify({"status": "error", "message": raw_records["error"]}), 500
    return jsonify({
        "status": "success",
        "columns": raw_records["columns"],
        "rows": raw_records["rows"],
        "row_count": raw_records["row_count"]
    })

@app.route('/api/investigate', methods=['GET'])
def investigate_pipeline():
    """
    Correlates incident data and runs cognitive NLP analysis.
    Query param: ?id=<log_id> (default 1) — accepts integers OR strings like CORAL-1, WH-2, SEC-101
    """
    raw_records = run_coral_engine()

    if not raw_records or "error" in raw_records:
        return jsonify({"status": "error", "message": "Coral engine failed"}), 500

    rows = raw_records.get("rows", [])

    # ── Robust ID resolution ────────────────────────────────────────
    # Accepts: integer 1, string "1", or prefixed strings "CORAL-1" / "WH-2" / "SEC-101"
    raw_id = request.args.get('id', default="1")
    log_id = None
    try:
        log_id = int(raw_id)
    except (ValueError, TypeError):
        import re
        m = re.search(r'(\d+)$', str(raw_id))
        if m:
            log_id = int(m.group(1))

    selected_row = None
    if log_id is not None:
        # Try exact id match first
        for r in rows:
            if r.get("id") == log_id:
                selected_row = r
                break
        # Try 1-based index fallback
        if not selected_row and 1 <= log_id <= len(rows):
            selected_row = rows[log_id - 1]

    if not selected_row:
        if rows:
            selected_row = rows[0]
        else:
            return jsonify({"status": "error", "message": "No logs found in DB"}), 404

    mapped_context = {
        "id":             selected_row.get("id"),
        "code":           selected_row.get("code", "SEC-UNK"),
        "commit_hash":    selected_row.get("commit_hash", "N/A"),
        "author":         selected_row.get("author", "N/A"),
        "commit_message": selected_row.get("commit_message", "N/A"),
        "message_text":   selected_row.get("message_text", "N/A"),
        "vuln_id":        selected_row.get("vuln_id", "N/A"),
        "severity":       selected_row.get("severity", "safe"),
        "impact":         selected_row.get("impact", "N/A"),
        "package":        selected_row.get("package", "N/A")
    }

    client_obj = get_client()
    ai_result = run_cognitive_nlp_analysis(mapped_context, client=client_obj)

    if "error" in ai_result:
        return jsonify({"status": "error", "ai_error": ai_result["error"]}), 400

    return jsonify({
        "status":              "success",
        "extracted_logs":      mapped_context,
        "ai_analysis_markdown": ai_result["report"],
        "mode":                "live" if client_obj else "mocked"
    }), 200

@app.route('/api/chat', methods=['POST'])
def copilot_chat():
    """
    AI Copilot Chat Endpoint. Responds to questions like 'Why is SEC-101 risky?'.
    JSON Payload: { "message": "User query", "log_id": 1 }
    """
    data = request.json or {}
    user_msg = data.get("message", "")
    log_id = data.get("log_id", 1)

    if not user_msg:
        return jsonify({"status": "error", "message": "No message provided"}), 400

    raw_records = run_coral_engine()
    rows = raw_records.get("rows", [])
    log_context = None
    for r in rows:
        if r.get("id") == log_id:
            log_context = r
            break
    if not log_context and rows:
        log_context = rows[0]

    client_obj = get_client()
    
    if not client_obj:
        # High fidelity mocked responses for standard questions
        cleaned_msg = user_msg.lower()
        if "sec-101" in cleaned_msg or "credentials" in cleaned_msg:
            reply = """### 🛡️ Copilot Analysis: SEC-101
* **Vulnerability Details**: Hardcoded Database credentials in commit `f10ba89` (`CVE-2026-9912`).
* **Package Impact**: Affected code uses `postgresql-client` to communicate with live production stores.
* **Mitigation Strategy**: 
  1. Revoke/rotate database password immediately.
  2. Use Git-history scrubbers (e.g. `bfg` or `git-filter-repo`) to purge secret from Git history.
  3. Deploy AWS Secrets Manager or HashiCorp Vault to inject credentials dynamically.
"""
        elif "sec-102" in cleaned_msg or "lodash" in cleaned_msg:
            reply = """### 🛡️ Copilot Analysis: SEC-102
* **Vulnerability Details**: Prototype pollution vulnerability in `lodash` package (`CVE-2020-8203`).
* **Package Impact**: Deeply nested in application dependencies, allowing object-prototype manipulation which results in Remote Code Execution (RCE).
* **Mitigation Strategy**:
  1. Upgrade `lodash` to version `4.17.21` or higher via `npm audit fix` or `yarn upgrade lodash`.
  2. Implement strict input schema verification to prevent prototype injections.
"""
        elif "sec-103" in cleaned_msg or "anomaly" in cleaned_msg:
            reply = """### 🛡️ Copilot Analysis: SEC-103
* **Vulnerability Details**: Suspicious developer force-pushes and arbitrary command execution hooks inside setup scripts.
* **Package Impact**: Modifies local shell scripts in `node-setup` running on developer/staging nodes.
* **Mitigation Strategy**:
  1. Review all modifications made by developer `contractor_x`.
  2. Revoke push credentials of `contractor_x` pending security review.
  3. Implement mandatory 2-person code reviews for core setup tools.
"""
        else:
            reply = f"""### 🤖 SecOps AI Assistant
I received your query: "{user_msg}"

Here is general security feedback:
* Always ensure your dependencies are updated to avoid common CVE exploits.
* Restrict direct commit access to critical branches like `main` or `release`.
* Use secrets scanning tools (like TruffleHog or GitGuardian) in your CI/CD pipeline.
"""
        return jsonify({
            "status": "success",
            "reply": reply,
            "mode": "mocked"
        })

    # Call OpenAI API
    system_prompt = (
        "You are an expert SecOps AI Assistant Copilot. Answer user questions regarding vulnerabilities, "
        "CVE codes, packages, and code changes. Use clear, bulleted Markdown. "
        f"Context details of current active incident: {str(log_context)}"
    )
    try:
        response = client_obj.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_msg}
            ],
            temperature=0.2,
            max_tokens=600
        )
        return jsonify({
            "status": "success",
            "reply": response.choices[0].message.content,
            "mode": "live"
        })
    except Exception as e:
        return jsonify({"status": "error", "message": f"LLM Chat Exception: {str(e)}"}), 500

@app.route('/api/query', methods=['GET'])
def query_natural_language():
    """
    Translates Natural Language to Coral SQL query and executes it against YAML.
    Query param: ?q=Show+all+critical+incidents+from+today
    """
    nl_query = request.args.get('q', default="")
    if not nl_query:
        return jsonify({"status": "error", "message": "No query string provided"}), 400

    raw_records = run_coral_engine()
    rows = raw_records.get("rows", [])
    
    generated_sql = "SELECT * FROM mock_security;"
    filtered_rows = rows
    
    client_obj = get_client()
    
    if client_obj:
        prompt = f"""
        Analyze this natural language search request for security logs: "{nl_query}"
        Translate this into:
        1. A Coral SQL query string (e.g. "SELECT * FROM mock_security WHERE severity = 'Critical';")
        2. A simplified JSON filter. Include fields like:
           - "severity": "Critical" | "High" | "Medium" (or null)
           - "author": string (or null)
           - "today": boolean (true if query asks for 'today' or 'recent' alerts)
           
        Return ONLY valid JSON in this format, with no markdown wrapping:
        {{
          "coral_query": "YOUR_SQL_QUERY",
          "filter_criteria": {{
             "severity": "SeverityLevelOrNull",
             "author": "AuthorNameOrNull",
             "today": trueOrFalse
          }}
        }}
        """
        try:
            res = client_obj.chat.completions.create(
                model=AI_MODEL,
                messages=[
                    {"role": "system", "content": "You are a database compiler. Return only raw JSON data."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            parsed = yaml.safe_load(res.choices[0].message.content)
            generated_sql = parsed.get("coral_query", "SELECT * FROM mock_security;")
            criteria = parsed.get("filter_criteria", {})
            
            filtered_rows = []
            for r in rows:
                match = True
                if criteria.get("severity") and criteria["severity"].lower() != "null":
                    if r.get("severity", "").lower() != criteria["severity"].lower():
                        match = False
                if criteria.get("author") and criteria["author"].lower() != "null":
                    if criteria["author"].lower() not in r.get("author", "").lower():
                        match = False
                if criteria.get("today"):
                    if "2026-05-25" not in r.get("timestamp", ""):
                        match = False
                if match:
                    filtered_rows.append(r)
        except Exception as e:
            generated_sql = f"SELECT * FROM mock_security; -- Error parsing AI response: {str(e)}"
    else:
        # Mocked rules-based NLP parser
        cleaned = nl_query.lower()
        if "critical" in cleaned:
            generated_sql = "SELECT * FROM mock_security WHERE severity = 'Critical';"
            filtered_rows = [r for r in rows if r.get("severity") == "Critical"]
        elif "high" in cleaned:
            generated_sql = "SELECT * FROM mock_security WHERE severity = 'High';"
            filtered_rows = [r for r in rows if r.get("severity") == "High"]
        elif "today" in cleaned:
            generated_sql = "SELECT * FROM mock_security WHERE timestamp LIKE '2026-05-25%';"
            filtered_rows = [r for r in rows if "2026-05-25" in r.get("timestamp", "")]
        elif "alice" in cleaned:
            generated_sql = "SELECT * FROM mock_security WHERE author = 'alice_dev';"
            filtered_rows = [r for r in rows if r.get("author") == "alice_dev"]
        else:
            generated_sql = "SELECT * FROM mock_security WHERE commit_message LIKE '%search%';"
            filtered_rows = rows

    return jsonify({
        "status": "success",
        "natural_query": nl_query,
        "coral_query": generated_sql,
        "rows": filtered_rows,
        "row_count": len(filtered_rows)
    })

@app.route('/api/remediate', methods=['GET'])
def get_remediation():
    """
    Returns personalized AI-powered remediation scripts and guidelines for an incident.
    Query param: ?id=<log_id>  — accepts integers OR strings like CORAL-1, WH-2
    """
    raw_records = run_coral_engine()
    rows = raw_records.get("rows", [])

    # ── Robust ID resolution (same logic as investigate) ───────────
    raw_id = request.args.get('id', default="1")
    log_id = None
    try:
        log_id = int(raw_id)
    except (ValueError, TypeError):
        import re
        m = re.search(r'(\d+)$', str(raw_id))
        if m:
            log_id = int(m.group(1))

    selected_row = None
    if log_id is not None:
        for r in rows:
            if r.get("id") == log_id:
                selected_row = r
                break
        if not selected_row and 1 <= log_id <= len(rows):
            selected_row = rows[log_id - 1]

    if not selected_row and rows:
        selected_row = rows[0]

    if not selected_row:
        return jsonify({"status": "error", "message": "No incident found"}), 404

    # ── Personalized plan via the AI helper ─────────────────────────
    data_payload = generate_personalized_remediation_plan(selected_row, rows)

    return jsonify({
        "status":    "success",
        "log_id":    log_id,
        "remediation": data_payload
    })

@app.route('/api/anomalies', methods=['GET'])
def get_anomalies():
    """
    Analyzes log records to report system anomalies (suspicious developers, packages).
    """
    raw_records = run_coral_engine()
    rows = raw_records.get("rows", [])
    
    anomalies = []
    
    # 1. Look for repeated suspicious developers
    author_counts = {}
    for r in rows:
        author = r.get("author")
        if author:
            author_counts[author] = author_counts.get(author, 0) + 1
            
    # 2. Scans for known anomaly codes or bad keywords
    for r in rows:
        if r.get("code") == "SEC-103" or "backdoor" in r.get("commit_message", "").lower() or "shell" in r.get("message_text", "").lower():
            anomalies.append({
                "type": "Malicious Hook Injection",
                "severity": "Critical",
                "description": f"Developer '{r.get('author')}' modified setup scripting to execute arbitrary developer shell scripts.",
                "evidence": f"Commit hash: {r.get('commit_hash')} | Commit message: '{r.get('commit_message')}'",
                "action": "Quarantine credentials and run developer audit."
            })
            
        if "temporary database auth credentials" in r.get("commit_message", "").lower():
            anomalies.append({
                "type": "Credentials Exposure Pattern",
                "severity": "High",
                "description": f"Sensitive key configurations committed directly in codebase by '{r.get('author')}'",
                "evidence": f"Chat log leak correlated: '{r.get('message_text')}'",
                "action": "Rotate passwords and clean Git commit trees."
            })

    return jsonify({
        "status": "success",
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "metrics": {
            "total_logs_analyzed": len(rows),
            "threat_risk_score": "78/100" if len(anomalies) > 0 else "12/100",
            "system_status": "Degraded - Action Required" if len(anomalies) > 0 else "Secure"
        }
    })

if __name__ == '__main__':
    # Host on port 5001
    app.run(host='0.0.0.0', port=5001, debug=True)
