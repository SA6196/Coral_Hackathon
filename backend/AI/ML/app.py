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
        # Fallback to high-quality template if OpenAI is offline
        return {
            "report": f"""### 🚨 SECURITY REPORT ({code})
            
#### 1. SUMMARY
Critical security alert identified. Developer **{author}** introduced a high-risk change related to **{pkg}**. 
* **Business Risk**: {impact}
* **Correlation Evidence**: Commit message "{commit_msg}" correlates directly with private chat alerts stating: *"{chat_msg}"*.

#### 2. ROOT CAUSE & WHY IT MATTERS
* **Why this matters**: Insecure handling of `{pkg}` vulnerabilities directly compromises internal service integrity. If left unpatched, it exposes live databases or services to untrusted execution vectors.
* **Exploit Possibilities**: Exploitation of `{vuln_id}` could lead to full credentials leaking or unauthorized shell execution depending on server permissions.

#### 3. RISK SCORE & SEVERITY IMPACT
* **Risk Score**: `9.8 / 10` (**{severity}** Severity)
* **Severity Impact**: Host take-over, administrative data compromise, and potential compliance violation of security standards (SOC2, GDPR).

#### 4. REMEDIATION & ROLLBACK SUGGESTIONS
* **Immediate Rollback**: Revert commit `{incident_matrix.get('commit_hash', 'HEAD')}` immediately.
* **Remediation**: Upgrade package `{pkg}` to secure release version, purge leaked configuration secrets, rotate database keys, and set up branch protection rules to prevent direct force pushes.
"""
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
        # Fix: Accessed index [0] to get the response content
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
    Query param: ?id=<log_id> (default 1)
    """
    log_id = request.args.get('id', default=1, type=int)
    raw_records = run_coral_engine()
    
    if not raw_records or "error" in raw_records:
        return jsonify({"status": "error", "message": "Coral engine failed"}), 500

    rows = raw_records.get("rows", [])
    selected_row = None
    for r in rows:
        if r.get("id") == log_id:
            selected_row = r
            break
            
    if not selected_row:
        if rows:
            selected_row = rows[0]
        else:
            return jsonify({"status": "error", "message": "No logs found in DB"}), 404

    # Fix: Correct mapping for rows. Extract actual values.
    mapped_context = {
        "id": selected_row.get("id"),
        "code": selected_row.get("code", "SEC-UNK"),
        "commit_hash": selected_row.get("commit_hash", "N/A"),
        "author": selected_row.get("author", "N/A"),
        "commit_message": selected_row.get("commit_message", "N/A"),
        "message_text": selected_row.get("message_text", "N/A"),
        "vuln_id": selected_row.get("vuln_id", "N/A"),
        "severity": selected_row.get("severity", "N/A"),
        "impact": selected_row.get("impact", "N/A"),
        "package": selected_row.get("package", "N/A")
    }
    
    client_obj = get_client()
    ai_result = run_cognitive_nlp_analysis(mapped_context, client=client_obj)
    
    if "error" in ai_result:
        return jsonify({"status": "error", "ai_error": ai_result["error"]}), 400

    return jsonify({
        "status": "success",
        "extracted_logs": mapped_context,
        "ai_analysis_markdown": ai_result["report"],
        "mode": "live" if client_obj else "mocked"
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
    Returns AI-powered actionable remediation scripts and guidelines for an incident.
    Query param: ?id=<log_id>
    """
    log_id = request.args.get('id', default=1, type=int)
    raw_records = run_coral_engine()
    rows = raw_records.get("rows", [])
    
    selected_row = None
    for r in rows:
        if r.get("id") == log_id:
            selected_row = r
            break
    if not selected_row and rows:
        selected_row = rows[0]

    code = selected_row.get("code", "SEC-101")
    pkg = selected_row.get("package", "N/A")
    commit_hash = selected_row.get("commit_hash", "HEAD")

    remediation_suggestions = {
        "SEC-101": {
            "title": "Purge Leaked Credentials & Deploy Secret Vault",
            "actions": [
                "Upgrade configurations to fetch DB credentials from environments",
                "Rollback the commit exposing DB password to git tree",
                "Rotate DB login passwords immediately",
                "Enable AWS Secrets Manager integration"
            ],
            "scripts": [
                f"# Step 1: Revert leaking commit\ngit revert {commit_hash}",
                "# Step 2: Install secret scanner pre-commit hook\npip install trufflehog\ntrufflehog git file:///path/to/repo --since-commit HEAD~5",
                "# Step 3: Set env values\nexport DB_PASSWORD=$(aws secretsmanager get-secret-value --secret-id DevDB --query SecretString)"
            ]
        },
        "SEC-102": {
            "title": "Upgrade Vulnerable NPM Dependencies",
            "actions": [
                "Upgrade vulnerable lodash package to secure version",
                "Run npm/yarn security audit checks",
                "Audit internal application logic for prototype injections"
            ],
            "scripts": [
                f"# Step 1: Upgrade dependency package\nnpm install {pkg}@4.17.21 --save",
                "# Step 2: Verify dependency graph security\nnpm audit --audit-level=high",
                "# Step 3: Rebuild deployment package\nnpm run build && docker build -t app:latest ."
            ]
        },
        "SEC-103": {
            "title": "Developer Privileges Audit & Branch Guards",
            "actions": [
                "Revert raw setup hook script modifications",
                "Suspend push permissions for developer contractor_x",
                "Configure Branch Protection rules on your repository"
            ],
            "scripts": [
                f"# Step 1: Reset active hooks\nrm -rf .git/hooks/pre-commit\ngit checkout HEAD -- setup.sh",
                "# Step 2: Set git repository branch guard (Github CLI)\ngh api -X PUT /repos/:owner/:repo/branches/main/protection -F required_pull_request_reviews.required_approving_review_count=2"
            ]
        }
    }

    data_payload = remediation_suggestions.get(code, {
        "title": "General Security Hardening & Patching",
        "actions": [
            "Upgrade core system packages",
            "Review developer code alterations",
            "Run static code scans"
        ],
        "scripts": [
            "git status\n# Review files carefully before committing",
            "git diff HEAD~1 HEAD"
        ]
    })

    return jsonify({
        "status": "success",
        "log_id": log_id,
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
