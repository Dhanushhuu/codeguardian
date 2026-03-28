import { useState, useEffect, useRef } from "react";

const API_BASE = "";

// ─── Design tokens ────────────────────────────────────────────────────────────
const css = `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=DM+Sans:wght@300;400;500;600&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:        #0a0a0f;
    --surface:   #111118;
    --surface2:  #1a1a24;
    --border:    #ffffff0f;
    --border2:   #ffffff1a;
    --text:      #e8e8f0;
    --muted:     #6b6b80;
    --accent:    #7c6aff;
    --accent2:   #4dffc3;
    --red:       #ff4d6a;
    --orange:    #ff8c42;
    --yellow:    #ffd166;
    --blue:      #4da6ff;
    --mono:      'JetBrains Mono', monospace;
    --sans:      'DM Sans', sans-serif;
    --radius:    10px;
    --radius-lg: 16px;
  }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
  }

  /* Subtle grid background */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(var(--border) 1px, transparent 1px),
      linear-gradient(90deg, var(--border) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  #root { position: relative; z-index: 1; }

  .app {
    max-width: 1100px;
    margin: 0 auto;
    padding: 40px 24px 80px;
  }

  /* Header */
  .header {
    display: flex;
    align-items: center;
    gap: 16px;
    margin-bottom: 48px;
    border-bottom: 1px solid var(--border2);
    padding-bottom: 24px;
  }

  .logo {
    width: 40px; height: 40px;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px; flex-shrink: 0;
  }

  .header-text h1 {
    font-family: var(--mono);
    font-size: 20px; font-weight: 700;
    letter-spacing: -0.5px;
    color: var(--text);
  }

  .header-text p {
    font-size: 12px;
    color: var(--muted);
    font-family: var(--mono);
  }

  .badge-version {
    margin-left: auto;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--accent2);
    background: #4dffc310;
    border: 1px solid #4dffc325;
    border-radius: 20px;
    padding: 3px 10px;
  }

  /* Panel */
  .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 24px;
    margin-bottom: 20px;
  }

  .panel-title {
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 16px;
  }

  /* Code input */
  .code-editor {
    width: 100%;
    min-height: 220px;
    background: var(--surface2);
    border: 1px solid var(--border2);
    border-radius: var(--radius);
    padding: 16px;
    font-family: var(--mono);
    font-size: 13px;
    color: var(--text);
    resize: vertical;
    outline: none;
    transition: border-color 0.2s;
    line-height: 1.7;
  }
  .code-editor:focus { border-color: var(--accent); }

  .input-row {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 12px;
    margin-bottom: 12px;
    align-items: center;
  }

  .filename-input {
    background: var(--surface2);
    border: 1px solid var(--border2);
    border-radius: var(--radius);
    padding: 8px 14px;
    font-family: var(--mono);
    font-size: 13px;
    color: var(--text);
    outline: none;
    width: 100%;
    transition: border-color 0.2s;
  }
  .filename-input:focus { border-color: var(--accent); }

  .lang-select {
    background: var(--surface2);
    border: 1px solid var(--border2);
    border-radius: var(--radius);
    padding: 8px 14px;
    font-family: var(--mono);
    font-size: 13px;
    color: var(--text);
    outline: none;
    cursor: pointer;
  }

  /* Buttons */
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 10px 20px;
    border-radius: var(--radius);
    font-family: var(--sans);
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    border: none;
    transition: all 0.15s;
    white-space: nowrap;
  }

  .btn-primary {
    background: var(--accent);
    color: #fff;
  }
  .btn-primary:hover:not(:disabled) { background: #6a59ee; transform: translateY(-1px); }
  .btn-primary:disabled { opacity: 0.4; cursor: not-allowed; }

  .btn-ghost {
    background: transparent;
    color: var(--muted);
    border: 1px solid var(--border2);
  }
  .btn-ghost:hover { color: var(--text); border-color: var(--border2); background: var(--surface2); }

  .btn-row { display: flex; gap: 10px; margin-top: 14px; flex-wrap: wrap; }

  /* Status bar */
  .status-bar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    font-family: var(--mono);
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 20px;
  }

  .status-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .dot-idle    { background: var(--muted); }
  .dot-running { background: var(--accent2); animation: pulse 1.2s ease-in-out infinite; }
  .dot-done    { background: var(--accent2); }
  .dot-error   { background: var(--red); }

  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50%       { opacity: 0.5; transform: scale(0.7); }
  }

  /* Event log */
  .event-log {
    max-height: 180px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .event-item {
    display: flex;
    gap: 12px;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--muted);
    align-items: flex-start;
  }

  .event-agent {
    color: var(--accent);
    min-width: 90px;
    flex-shrink: 0;
  }

  /* Verdict banner */
  .verdict-banner {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 20px 24px;
    border-radius: var(--radius-lg);
    border: 1px solid;
    margin-bottom: 20px;
  }
  .verdict-approve  { border-color: #4dffc340; background: #4dffc308; }
  .verdict-comment  { border-color: #ffd16640; background: #ffd16608; }
  .verdict-changes  { border-color: #ff4d6a40; background: #ff4d6a08; }

  .verdict-icon { font-size: 28px; flex-shrink: 0; }

  .verdict-label {
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 2px;
  }

  .verdict-title {
    font-size: 18px;
    font-weight: 600;
    color: var(--text);
  }

  .verdict-summary {
    font-size: 13px;
    color: var(--muted);
    margin-top: 4px;
  }

  /* Severity grid */
  .sev-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
    margin-bottom: 20px;
  }

  .sev-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px;
    text-align: center;
  }

  .sev-count {
    font-family: var(--mono);
    font-size: 28px;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 6px;
  }

  .sev-label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--muted);
    font-family: var(--mono);
  }

  .c-critical { color: var(--red); }
  .c-high     { color: var(--orange); }
  .c-medium   { color: var(--yellow); }
  .c-low      { color: var(--blue); }

  /* Issues list */
  .issue-item {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 14px 16px;
    margin-bottom: 10px;
    transition: border-color 0.15s;
    cursor: default;
  }
  .issue-item:hover { border-color: var(--border2); }

  .issue-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 6px;
    flex-wrap: wrap;
  }

  .issue-severity {
    font-family: var(--mono);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1px;
    padding: 2px 8px;
    border-radius: 4px;
    text-transform: uppercase;
  }
  .sev-critical { background: #ff4d6a20; color: var(--red);    border: 1px solid #ff4d6a30; }
  .sev-high     { background: #ff8c4220; color: var(--orange); border: 1px solid #ff8c4230; }
  .sev-medium   { background: #ffd16620; color: var(--yellow); border: 1px solid #ffd16630; }
  .sev-low      { background: #4da6ff20; color: var(--blue);   border: 1px solid #4da6ff30; }

  .issue-source {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--muted);
    background: var(--surface2);
    padding: 2px 8px;
    border-radius: 4px;
  }

  .issue-category {
    font-weight: 500;
    font-size: 14px;
    color: var(--text);
  }

  .issue-file {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    margin-left: auto;
  }

  .issue-desc {
    font-size: 13px;
    color: var(--muted);
    line-height: 1.5;
  }

  .fp-badge {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--muted);
    background: var(--surface2);
    padding: 2px 8px;
    border-radius: 4px;
    text-decoration: line-through;
    opacity: 0.5;
  }

  /* Code block */
  .code-block {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 12px;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--text);
    overflow-x: auto;
    white-space: pre;
    margin-top: 8px;
    line-height: 1.6;
  }

  /* Fix / test card */
  .fix-card {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px;
    margin-bottom: 12px;
  }

  .fix-title {
    font-size: 13px;
    font-weight: 500;
    color: var(--text);
    margin-bottom: 4px;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .fix-validated {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--accent2);
    background: #4dffc310;
    border: 1px solid #4dffc320;
    padding: 2px 7px;
    border-radius: 4px;
  }

  .fix-warn {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--yellow);
    background: #ffd16610;
    border: 1px solid #ffd16620;
    padding: 2px 7px;
    border-radius: 4px;
  }

  .diff-row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px; }
  .diff-label {
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-bottom: 4px;
  }
  .diff-before { color: var(--red); }
  .diff-after  { color: var(--accent2); }

  /* Tabs */
  .tabs {
    display: flex;
    gap: 4px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 20px;
  }
  .tab {
    padding: 10px 18px;
    font-size: 13px;
    font-weight: 500;
    color: var(--muted);
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: all 0.15s;
    border-radius: 0;
    background: none;
    border-top: none;
    border-left: none;
    border-right: none;
    font-family: var(--sans);
  }
  .tab:hover  { color: var(--text); }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }

  .tab-count {
    font-family: var(--mono);
    font-size: 10px;
    background: var(--surface2);
    padding: 1px 6px;
    border-radius: 8px;
    margin-left: 5px;
  }

  /* Empty state */
  .empty {
    text-align: center;
    padding: 40px;
    color: var(--muted);
    font-family: var(--mono);
    font-size: 13px;
  }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: var(--surface); }
  ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }

  @media (max-width: 640px) {
    .sev-grid    { grid-template-columns: repeat(2, 1fr); }
    .diff-row    { grid-template-columns: 1fr; }
    .input-row   { grid-template-columns: 1fr; }
  }
`;

// ─── Severity helpers ─────────────────────────────────────────────────────────

const SEV_CLASS = { critical: "sev-critical", high: "sev-high", medium: "sev-medium", low: "sev-low" };
const SEV_COLOR = { critical: "c-critical",   high: "c-high",   medium: "c-medium",   low: "c-low"   };
const SEV_ICON  = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵" };

const VERDICT_CONFIG = {
  approve:         { icon: "✅", label: "Approved",         cls: "verdict-approve" },
  comment:         { icon: "⚠️", label: "Needs Attention",  cls: "verdict-comment" },
  request_changes: { icon: "🚫", label: "Changes Required", cls: "verdict-changes" },
};

// ─── Sample vulnerable code for quick testing ─────────────────────────────────

const SAMPLE_CODE = `import pickle
import subprocess
import hashlib

def authenticate(username, password):
    # Hardcoded credentials — never do this
    if password == "admin123":
        return True
    return False

def get_user(user_id, cursor):
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()

def run_command(user_input):
    # Shell injection vulnerability
    result = subprocess.run(user_input, shell=True, capture_output=True)
    return result.stdout

def load_session(data):
    # Insecure deserialization
    return pickle.loads(data)

def hash_password(password):
    # Weak cryptography
    return hashlib.md5(password.encode()).hexdigest()
`;

// ─── Components ───────────────────────────────────────────────────────────────

function IssueItem({ issue }) {
  const [open, setOpen] = useState(false);
  const isFP = issue.false_positive;

  return (
    <div
      className="issue-item"
      style={{ opacity: isFP ? 0.5 : 1 }}
      onClick={() => setOpen(o => !o)}
    >
      <div className="issue-header">
        <span className={`issue-severity ${SEV_CLASS[issue.severity] || ""}`}>
          {issue.severity}
        </span>
        <span className="issue-source">{issue.source}</span>
        <span className="issue-category">{issue.category}</span>
        {isFP && <span className="fp-badge">false positive</span>}
        <span className="issue-file">{issue.filename}:{issue.line}</span>
      </div>
      <div className="issue-desc">{issue.description}</div>
      {open && issue.code_snippet && (
        <div className="code-block">{issue.code_snippet}</div>
      )}
      {open && isFP && issue.fp_reason && (
        <div style={{ marginTop: 8, fontSize: 12, color: "var(--muted)", fontFamily: "var(--mono)" }}>
          Dismissed: {issue.fp_reason}
        </div>
      )}
    </div>
  );
}

function FixCard({ fix }) {
  return (
    <div className="fix-card">
      <div className="fix-title">
        <span>{fix.filename}</span>
        <span className={fix.validated ? "fix-validated" : "fix-warn"}>
          {fix.validated ? "✓ syntax valid" : "⚠ needs review"}
        </span>
      </div>
      <div style={{ fontSize: 13, color: "var(--muted)", marginBottom: 8 }}>{fix.description}</div>
      <div className="diff-row">
        <div>
          <div className="diff-label diff-before">Before</div>
          <div className="code-block" style={{ borderColor: "#ff4d6a20" }}>{fix.original}</div>
        </div>
        <div>
          <div className="diff-label diff-after">After</div>
          <div className="code-block" style={{ borderColor: "#4dffc320" }}>{fix.fixed}</div>
        </div>
      </div>
      {fix.explanation && (
        <div style={{ marginTop: 10, fontSize: 12, color: "var(--muted)" }}>{fix.explanation}</div>
      )}
    </div>
  );
}

function TestCard({ test }) {
  return (
    <div className="fix-card">
      <div className="fix-title">
        <span>{test.filename}</span>
        <span className="fix-validated">{test.framework}</span>
      </div>
      <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 8 }}>
        Covers: {(test.covers || []).join(", ")}
      </div>
      <div className="code-block" style={{ maxHeight: 300, overflow: "auto" }}>
        {test.content}
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────

export default function App() {
  const [filename, setFilename]     = useState("app.py");
  const [language, setLanguage]     = useState("python");
  const [code, setCode]             = useState(SAMPLE_CODE);
  const [status, setStatus]         = useState("idle");   // idle | running | complete | failed
  const [reviewId, setReviewId]     = useState(null);
  const [events, setEvents]         = useState([]);
  const [report, setReport]         = useState(null);
  const [activeTab, setActiveTab]   = useState("security");
  const [statusMsg, setStatusMsg]   = useState("Ready to review");
  const esRef                       = useRef(null);
  const logRef                      = useRef(null);

  // Auto-scroll event log
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [events]);

  // Cleanup SSE on unmount
  useEffect(() => () => esRef.current?.close(), []);

  async function startReview() {
    if (!code.trim()) return;

    setStatus("running");
    setReport(null);
    setEvents([]);
    setStatusMsg("Queueing review…");

    try {
      const res = await fetch(`${API_BASE}/review`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          files: [{ filename, language, content: code, patch: "", additions: 0, deletions: 0 }],
        }),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const { review_id } = await res.json();
      setReviewId(review_id);
      setStatusMsg(`Running — ${review_id.slice(0, 8)}`);

      // Start SSE stream
      const es = new EventSource(`${API_BASE}/stream/${review_id}`);
      esRef.current = es;

      es.onmessage = async (e) => {
        const data = JSON.parse(e.data);

        if (data.done) {
          es.close();
          if (data.status === "complete") {
            // Fetch full results
            const rr = await fetch(`${API_BASE}/results/${review_id}`);
            const report = await rr.json();
            setReport(report);
            setStatus("complete");
            setStatusMsg(`Complete — ${report.verdict?.replace("_", " ") || "done"}`);
          } else {
            setStatus("failed");
            setStatusMsg("Review failed — check server logs");
          }
          return;
        }

        if (data.agent) {
          setEvents(ev => [...ev, data]);
          setStatusMsg(`${data.agent}: ${data.message}`);
        }
      };

      es.onerror = () => {
        es.close();
        setStatus("failed");
        setStatusMsg("Connection lost — is the server running?");
      };

    } catch (err) {
      setStatus("failed");
      setStatusMsg(`Error: ${err.message}`);
    }
  }

  function loadSample() {
    setCode(SAMPLE_CODE);
    setFilename("app.py");
    setLanguage("python");
  }

  function reset() {
    setStatus("idle");
    setReport(null);
    setEvents([]);
    setReviewId(null);
    setStatusMsg("Ready to review");
    esRef.current?.close();
  }

  const securityIssues = report?.security_issues || [];
  const realIssues     = securityIssues.filter(i => !i.false_positive);
  const fpIssues       = securityIssues.filter(i => i.false_positive);
  const qualityIssues  = report?.quality_issues  || [];
  const fixes          = report?.fixes            || [];
  const tests          = report?.tests            || [];
  const breakdown      = report?.severity_breakdown || {};
  const verdictCfg     = VERDICT_CONFIG[report?.verdict] || {};

  const dotClass = { idle: "dot-idle", running: "dot-running", complete: "dot-done", failed: "dot-error" }[status];

  return (
    <>
      <style>{css}</style>
      <div className="app">

        {/* Header */}
        <div className="header">
          <div className="logo">🛡</div>
          <div className="header-text">
            <h1>CodeGuardian</h1>
            <p>autonomous code security &amp; quality review</p>
          </div>
          <span className="badge-version">v1.0.0</span>
        </div>

        {/* Input Panel */}
        <div className="panel">
          <div className="panel-title">Code to Review</div>
          <div className="input-row">
            <input
              className="filename-input"
              value={filename}
              onChange={e => setFilename(e.target.value)}
              placeholder="filename e.g. app.py"
            />
            <select className="lang-select" value={language} onChange={e => setLanguage(e.target.value)}>
              <option value="python">Python</option>
              <option value="javascript">JavaScript</option>
              <option value="typescript">TypeScript</option>
              <option value="jsx">JSX</option>
              <option value="tsx">TSX</option>
            </select>
          </div>
          <textarea
            className="code-editor"
            value={code}
            onChange={e => setCode(e.target.value)}
            placeholder="Paste your code here…"
            spellCheck={false}
          />
          <div className="btn-row">
            <button
              className="btn btn-primary"
              onClick={startReview}
              disabled={status === "running" || !code.trim()}
            >
              {status === "running" ? "⟳ Reviewing…" : "▶ Run Review"}
            </button>
            <button className="btn btn-ghost" onClick={loadSample}>Load Sample</button>
            {status !== "idle" && (
              <button className="btn btn-ghost" onClick={reset}>Reset</button>
            )}
          </div>
        </div>

        {/* Status bar */}
        <div className="status-bar">
          <div className={`status-dot ${dotClass}`} />
          <span>{statusMsg}</span>
          {reviewId && (
            <span style={{ marginLeft: "auto", opacity: 0.4, fontFamily: "var(--mono)", fontSize: 11 }}>
              {reviewId.slice(0, 8)}
            </span>
          )}
        </div>

        {/* Event log */}
        {events.length > 0 && (
          <div className="panel" style={{ padding: "16px 20px" }}>
            <div className="panel-title">Agent log</div>
            <div className="event-log" ref={logRef}>
              {events.map((ev, i) => (
                <div className="event-item" key={i}>
                  <span className="event-agent">[{ev.agent}]</span>
                  <span>{ev.message}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Results */}
        {report && (
          <>
            {/* Verdict banner */}
            <div className={`verdict-banner ${verdictCfg.cls}`}>
              <div className="verdict-icon">{verdictCfg.icon}</div>
              <div>
                <div className="verdict-label">Verdict</div>
                <div className="verdict-title">{verdictCfg.label}</div>
                <div className="verdict-summary">{report.summary}</div>
              </div>
            </div>

            {/* Severity breakdown */}
            <div className="sev-grid">
              {[
                { key: "critical", label: "Critical" },
                { key: "high",     label: "High"     },
                { key: "medium",   label: "Medium"   },
                { key: "low",      label: "Low"       },
              ].map(({ key, label }) => (
                <div className="sev-card" key={key}>
                  <div className={`sev-count ${SEV_COLOR[key]}`}>{breakdown[key] ?? 0}</div>
                  <div className="sev-label">{label}</div>
                </div>
              ))}
            </div>

            {/* Tabs */}
            <div className="tabs">
              {[
                { key: "security", label: "Security",   count: realIssues.length  },
                { key: "quality",  label: "Quality",    count: qualityIssues.length },
                { key: "fixes",    label: "Fixes",      count: fixes.length       },
                { key: "tests",    label: "Tests",      count: tests.length       },
                { key: "fp",       label: "Dismissed",  count: fpIssues.length    },
              ].map(t => (
                <button
                  key={t.key}
                  className={`tab ${activeTab === t.key ? "active" : ""}`}
                  onClick={() => setActiveTab(t.key)}
                >
                  {t.label}
                  <span className="tab-count">{t.count}</span>
                </button>
              ))}
            </div>

            {/* Tab content */}
            {activeTab === "security" && (
              realIssues.length
                ? realIssues.map(i => <IssueItem key={i.id} issue={i} />)
                : <div className="empty">✅ No security issues found</div>
            )}

            {activeTab === "quality" && (
              qualityIssues.length
                ? qualityIssues.map(i => <IssueItem key={i.id} issue={i} />)
                : <div className="empty">✅ No quality issues found</div>
            )}

            {activeTab === "fixes" && (
              fixes.length
                ? fixes.map(f => <FixCard key={f.issue_id} fix={f} />)
                : <div className="empty">No fixes generated</div>
            )}

            {activeTab === "tests" && (
              tests.length
                ? tests.map(t => <TestCard key={t.filename} test={t} />)
                : <div className="empty">No tests generated</div>
            )}

            {activeTab === "fp" && (
              fpIssues.length
                ? fpIssues.map(i => <IssueItem key={i.id} issue={i} />)
                : <div className="empty">No false positives dismissed</div>
            )}
          </>
        )}

      </div>
    </>
  );
}