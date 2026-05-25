const API_BASE = 'http://localhost:5001';
let selectedLogId = 1;
let allLogs = [];

// Markdown to HTML simple parser
function compileMarkdown(markdown) {
    if (!markdown) return '';
    let html = markdown
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
    
    // Bold headers
    html = html.replace(/^### (.*$)/gim, '<h3><i class="fa-solid fa-square-poll-horizontal" style="color: var(--color-cyan);"></i> $1</h3>');
    html = html.replace(/^#### (.*$)/gim, '<h4>$1</h4>');
    
    // Bold lists
    html = html.replace(/^\* \*\*(.*?)\*\*:(.*$)/gim, '<li><strong style="color: var(--text-primary);">$1</strong>: $2</li>');
    html = html.replace(/^\* (.*$)/gim, '<li>$1</li>');
    html = html.replace(/- \*\*(.*?)\*\*:(.*$)/gim, '<li><strong style="color: var(--text-primary);">$1</strong>: $2</li>');
    html = html.replace(/- (.*$)/gim, '<li>$1</li>');
    
    // Bold / Inline Code
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/`(.*?)`/g, '<code>$1</code>');
    
    // Wrap lists
    html = html.replace(/(<li>.*<\/li>)/g, '<ul>$1</ul>');
    // Clean redundant nested ul lists
    html = html.replace(/<\/ul>\s*<ul>/g, '');
    
    // Split paragraphs
    html = html.replace(/([^>\r\n]+?)(\r\n|\n)/g, '<p>$1</p>');
    
    return html;
}

// Fetch headers utility
function getRequestHeaders() {
    const headers = {
        'Content-Type': 'application/json'
    };
    const keyVal = document.getElementById('openai-key-input').value;
    if (keyVal && keyVal.trim()) {
        headers['X-OpenAI-Key'] = keyVal.trim();
    }
    return headers;
}

// Initial Launch
window.addEventListener('DOMContentLoaded', () => {
    init();
    
    // Event listeners
    document.getElementById('trigger-investigate-btn').addEventListener('click', runAIScan);
    document.getElementById('nl-search-btn').addEventListener('click', executeNLSearch);
    document.getElementById('nl-search-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') executeNLSearch();
    });
    
    document.getElementById('chat-send-btn').addEventListener('click', sendChat);
    document.getElementById('chat-user-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendChat();
    });
});

async function init() {
    await fetchLogs();
    await fetchAnomalies();
    if (allLogs.length > 0) {
        selectIncident(allLogs[0].id);
    }
}

// Fetch Log Data
async function fetchLogs() {
    const tableBody = document.getElementById('logs-table-body');
    try {
        const response = await fetch(`${API_BASE}/api/logs`, {
            headers: getRequestHeaders()
        });
        const data = await response.json();
        
        if (data.status === 'success') {
            allLogs = data.rows;
            populateLogsTable(allLogs);
        } else {
            tableBody.innerHTML = `<tr><td colspan="5" style="color: var(--color-critical); text-align: center;">${data.message}</td></tr>`;
        }
    } catch (e) {
        tableBody.innerHTML = `<tr><td colspan="5" style="color: var(--color-critical); text-align: center;">Failed to connect to backend server on port 5001. Start the server via command line.</td></tr>`;
    }
}

function populateLogsTable(logs) {
    const tableBody = document.getElementById('logs-table-body');
    if (logs.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="5" style="color: var(--text-secondary); text-align: center;">No matching security records found.</td></tr>`;
        return;
    }
    
    tableBody.innerHTML = '';
    logs.forEach(log => {
        const tr = document.createElement('tr');
        tr.className = `log-row ${log.id === selectedLogId ? 'selected' : ''}`;
        tr.id = `log-row-${log.id}`;
        tr.onclick = () => selectIncident(log.id);
        
        let sevClass = 'badge-medium';
        if (log.severity.toLowerCase() === 'critical') sevClass = 'badge-critical';
        if (log.severity.toLowerCase() === 'high') sevClass = 'badge-high';
        
        // Clean date format
        const cleanDate = new Date(log.timestamp).toLocaleString();
        
        tr.innerHTML = `
            <td>
                <div style="font-weight: 600; color: var(--color-cyan);">${log.code}</div>
                <div style="font-size: 0.7rem; color: var(--text-muted); text-overflow: ellipsis; max-width: 150px; overflow: hidden; white-space: nowrap;">${log.commit_message}</div>
            </td>
            <td><span class="badge ${sevClass}">${log.severity}</span></td>
            <td style="color: var(--text-secondary);">${log.author}</td>
            <td style="font-family: 'Fira Code', monospace; font-size: 0.75rem;">${log.vuln_id}</td>
            <td style="font-size: 0.75rem; color: var(--text-muted);">${cleanDate}</td>
        `;
        tableBody.appendChild(tr);
    });
}

// Fetch System Anomalies
async function fetchAnomalies() {
    const container = document.getElementById('anomaly-container');
    const badge = document.getElementById('anomaly-badge-count');
    const scoreVal = document.getElementById('threat-score-val');
    const scoreStatus = document.getElementById('system-status-text');
    
    try {
        const response = await fetch(`${API_BASE}/api/anomalies`, {
            headers: getRequestHeaders()
        });
        const data = await response.json();
        
        if (data.status === 'success') {
            badge.innerText = `${data.anomaly_count} Alert${data.anomaly_count !== 1 ? 's' : ''}`;
            scoreVal.innerText = data.metrics.threat_risk_score;
            scoreStatus.innerText = data.metrics.system_status.split(' - ')[0];
            
            if (data.anomaly_count > 0) {
                document.getElementById('db-status-dot').className = 'status-dot anomaly-active';
            } else {
                document.getElementById('db-status-dot').className = 'status-dot';
            }
            
            container.innerHTML = '';
            data.anomalies.forEach(anomaly => {
                const card = document.createElement('div');
                card.className = 'anomaly-card';
                card.innerHTML = `
                    <div class="anomaly-header">
                        <span class="anomaly-type">${anomaly.type}</span>
                        <span class="anomaly-badge">${anomaly.severity}</span>
                    </div>
                    <div class="anomaly-desc">${anomaly.description}</div>
                    <div class="anomaly-evidence">${anomaly.evidence}</div>
                `;
                container.appendChild(card);
            });
        }
    } catch (e) {
        container.innerHTML = '<div style="color: var(--text-muted); font-size: 0.75rem; padding: 1rem;">Offline.</div>';
    }
}

// Select incident event handler
function selectIncident(id) {
    selectedLogId = id;
    
    // Update table selections
    document.querySelectorAll('.log-row').forEach(row => {
        row.classList.remove('selected');
    });
    const activeRow = document.getElementById(`log-row-${id}`);
    if (activeRow) activeRow.classList.add('selected');
    
    const selectedLog = allLogs.find(l => l.id === id);
    if (!selectedLog) return;
    
    // Update tabs default contents
    document.getElementById('node-commit-desc').innerText = selectedLog.commit_hash;
    document.getElementById('node-chat-desc').innerText = selectedLog.author;
    document.getElementById('node-vuln-desc').innerText = selectedLog.vuln_id;
    
    document.getElementById('correlation-summary-text').innerHTML = `
        Git commit hash <strong>${selectedLog.commit_hash}</strong> by <strong>${selectedLog.author}</strong> was flagged for modifying 
        the package <strong>${selectedLog.package}</strong>. Private team chat records correlate with this event, showing developer discussion of: 
        <em>"${selectedLog.message_text}"</em>. Cross-reference indicates vulnerability database maps this to threat code <strong>${selectedLog.vuln_id}</strong>.
    `;
    
    // Clear AI report box until Run AI Scan is clicked
    document.getElementById('ai-report-box').innerHTML = `
        <div style="text-align: center; padding: 2rem; color: var(--text-muted);">
            <i class="fa-solid fa-robot" style="font-size: 2rem; color: var(--border-glass); margin-bottom: 0.5rem; display: block;"></i>
            Click "Run AI Scan" to analyze this correlation and produce an executive markdown report.
        </div>
    `;
    
    // Get remediation actions
    fetchRemediation(id);
}

// Run AI NLP Scanner
async function runAIScan() {
    const scanner = document.getElementById('scanner-bar');
    const reportBox = document.getElementById('ai-report-box');
    const aiDot = document.getElementById('ai-status-dot');
    const aiText = document.getElementById('ai-status-text');
    
    scanner.style.display = 'block';
    reportBox.innerHTML = `
        <div style="text-align: center; padding: 3rem; color: var(--text-secondary);">
            <i class="fa-solid fa-spinner fa-spin" style="font-size: 1.5rem; color: var(--color-cyan); margin-bottom: 0.75rem; display: block;"></i>
            AI Copilot is correlating logs, querying CVE database and compiling report...
        </div>
    `;
    
    switchTab('tab-report');
    
    try {
        const response = await fetch(`${API_BASE}/api/investigate?id=${selectedLogId}`, {
            headers: getRequestHeaders()
        });
        const data = await response.json();
        
        scanner.style.display = 'none';
        
        if (data.status === 'success') {
            const htmlReport = compileMarkdown(data.ai_analysis_markdown);
            reportBox.innerHTML = `
                <div style="display:flex; justify-content: space-between; align-items:center; margin-bottom: 1rem; border-bottom: 1px solid var(--border-glass); padding-bottom: 0.5rem;">
                    <span style="font-size: 0.7rem; color: var(--text-muted); font-family: monospace;">MODE: ${data.mode.toUpperCase()}</span>
                    <button class="copy-btn" onclick="copyReportText()" style="position:relative; top:0; right:0;"><i class="fa-regular fa-copy"></i> Copy Markdown</button>
                </div>
                <div id="raw-markdown-content" style="display:none;">${data.ai_analysis_markdown}</div>
                ${htmlReport}
            `;
            
            aiDot.style.backgroundColor = 'var(--color-success)';
            aiText.innerText = 'AI Engine: Connected';
        } else {
            reportBox.innerHTML = `<div style="color: var(--color-critical); padding: 1.5rem; text-align: center;"><i class="fa-solid fa-triangle-exclamation"></i> Analysis Failed: ${data.ai_error}</div>`;
        }
    } catch (e) {
        scanner.style.display = 'none';
        reportBox.innerHTML = `<div style="color: var(--color-critical); padding: 1.5rem; text-align: center;"><i class="fa-solid fa-triangle-exclamation"></i> Network error connecting to OpenAI pipeline.</div>`;
    }
}

// Fetch Remediation Commands
async function fetchRemediation(id) {
    const box = document.getElementById('remediation-box');
    try {
        const response = await fetch(`${API_BASE}/api/remediate?id=${id}`, {
            headers: getRequestHeaders()
        });
        const data = await response.json();
        
        if (data.status === 'success') {
            const rem = data.remediation;
            
            let stepsHtml = '';
            rem.actions.forEach(act => {
                stepsHtml += `<div class="step-item">${act}</div>`;
            });
            
            let scriptsHtml = '';
            rem.scripts.forEach((script, idx) => {
                scriptsHtml += `
                    <div style="position: relative; margin-top: 0.5rem;">
                        <div class="code-terminal" id="terminal-code-${idx}">${script}</div>
                        <button class="copy-btn" onclick="copyTerminalText(${idx})"><i class="fa-regular fa-copy"></i> Copy</button>
                    </div>
                `;
            });
            
            box.innerHTML = `
                <div class="remediation-header">
                    <i class="fa-solid fa-wrench" style="margin-right: 0.4rem;"></i>
                    ${rem.title}
                </div>
                <div class="action-steps">
                    ${stepsHtml}
                </div>
                <div style="font-size: 0.8rem; font-weight: 600; margin-top: 0.5rem; color: var(--text-secondary);">Remediation Shell Scripts</div>
                ${scriptsHtml}
            `;
        }
    } catch (e) {
        box.innerHTML = '<div style="color: var(--text-muted); font-size: 0.8rem; text-align: center; padding: 2rem;">Offline.</div>';
    }
}

// NL Query Engine Search
async function executeNLSearch() {
    const val = document.getElementById('nl-search-input').value;
    const logLabel = document.getElementById('generated-query-log');
    
    if (!val || !val.trim()) return;
    
    logLabel.innerHTML = `→ Coral Query: <i class="fa-solid fa-spinner fa-spin"></i> Translating...`;
    
    try {
        const response = await fetch(`${API_BASE}/api/query?q=${encodeURIComponent(val)}`, {
            headers: getRequestHeaders()
        });
        const data = await response.json();
        
        if (data.status === 'success') {
            logLabel.innerText = `→ Coral Query: ${data.coral_query}`;
            populateLogsTable(data.rows);
            
            // Auto select the first matching row if any
            if (data.rows.length > 0) {
                selectIncident(data.rows[0].id);
            }
        }
    } catch (e) {
        logLabel.innerText = `→ Error connecting to NL compilation engine`;
    }
}

// Chat functions
async function sendChat() {
    const input = document.getElementById('chat-user-input');
    const msg = input.value;
    if (!msg || !msg.trim()) return;
    
    input.value = '';
    
    appendMessage(msg, 'user');
    
    // Add loader bubble
    const messagesBox = document.getElementById('chat-messages-container');
    const loader = document.createElement('div');
    loader.className = 'chat-msg assistant shimmer-loading';
    loader.id = 'chat-bot-loader';
    loader.innerHTML = `
        <div style="font-size: 0.8rem; color: var(--text-muted);">
            <i class="fa-solid fa-circle-notch fa-spin"></i> Copilot responding...
        </div>
    `;
    messagesBox.appendChild(loader);
    messagesBox.scrollTop = messagesBox.scrollHeight;
    
    try {
        const response = await fetch(`${API_BASE}/api/chat`, {
            method: 'POST',
            headers: getRequestHeaders(),
            body: JSON.stringify({
                message: msg,
                log_id: selectedLogId
            })
        });
        const data = await response.json();
        
        // Remove loader
        const ld = document.getElementById('chat-bot-loader');
        if (ld) ld.remove();
        
        if (data.status === 'success') {
            appendMessage(data.reply, 'assistant');
        } else {
            appendMessage('An error occurred during conversational retrieval.', 'assistant');
        }
    } catch (e) {
        const ld = document.getElementById('chat-bot-loader');
        if (ld) ld.remove();
        appendMessage('Network connection error contacting AI chatbot.', 'assistant');
    }
}

function appendMessage(text, role) {
    const messagesBox = document.getElementById('chat-messages-container');
    const div = document.createElement('div');
    div.className = `chat-msg ${role}`;
    
    if (role === 'assistant') {
        div.innerHTML = compileMarkdown(text);
    } else {
        div.innerText = text;
    }
    
    messagesBox.appendChild(div);
    messagesBox.scrollTop = messagesBox.scrollHeight;
}

function sendSuggested(prompt) {
    document.getElementById('chat-user-input').value = prompt;
    sendChat();
}

// Tab switcher
function switchTab(tabId) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelectorAll('.tab-content').forEach(cont => {
        cont.classList.remove('active');
    });
    
    // Find matching button
    const btn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick').includes(tabId));
    if (btn) btn.classList.add('active');
    
    const activeContent = document.getElementById(tabId);
    if (activeContent) activeContent.classList.add('active');
}

// Clipboard utilities
function copyTerminalText(idx) {
    const el = document.getElementById(`terminal-code-${idx}`);
    if (el) {
        navigator.clipboard.writeText(el.innerText);
        showTemporaryToast("Copied script code to clipboard");
    }
}

function copyReportText() {
    const el = document.getElementById('raw-markdown-content');
    if (el) {
        navigator.clipboard.writeText(el.innerText);
        showTemporaryToast("Copied incident report markdown");
    }
}

function showTemporaryToast(message) {
    let toast = document.getElementById('toast-msg-notify');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast-msg-notify';
        toast.style.cssText = 'position:fixed; bottom: 20px; left: 50%; transform: translateX(-50%); background: rgba(0,250,250,0.9); color:#000; font-weight:700; padding: 0.5rem 1.5rem; border-radius:30px; font-size: 0.8rem; z-index:9999; box-shadow: 0 4px 15px rgba(0,0,0,0.3); transition: opacity 0.3s; pointer-events:none;';
        document.body.appendChild(toast);
    }
    toast.innerText = message;
    toast.style.opacity = '1';
    setTimeout(() => {
        toast.style.opacity = '0';
    }, 2000);
}
