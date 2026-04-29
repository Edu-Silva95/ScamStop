import { useState } from "react";

/* ---------------- TONES ---------------- */
function statusTone(status) {
  if (status === "malicious") return "bad";
  if (status === "suspicious") return "warn";
  if (status === "neutral") return "neutral";
  return "good";
}

function verdictTone(verdict) {
  if (verdict === "official") return "good";
  if (["lookalike", "invalid", "impersonation"].includes(verdict)) return "bad";
  if (["shortener", "unverified"].includes(verdict)) return "warn";
  return "neutral";
}

/* ---------------- TOAST ---------------- */
function Toast({ toast }) {
  if (!toast) return null;

  return (
    <div className={`toast toast--${toast.type}`}>
      {toast.message}
    </div>
  );
}

/* ---------------- LOADER ---------------- */
function Loader() {
  return (
    <div className="loader">
      <div className="scan-loader" />
      <p>Scanning message…</p>
    </div>
  );
}

/* ---------------- SCORE GAUGE ---------------- */
function ScoreGauge({ score, status }) {
  const safeScore = Math.max(0, Math.min(100, score || 0));

  const tone =
    status === "malicious"
      ? "bad"
      : status === "suspicious"
        ? "warn"
        : status === "neutral"
          ? "neutral"
        : "good";

  return (
    <div className="score-wrap">
      <div className="score-meter">
        <div
          className={`score-meter__fill fill--${tone}`}
          style={{ width: `${safeScore}%` }}
        />
      </div>

      <div className="score-meta">
        <div className="score-label">
          Risk Score: <strong>{safeScore}</strong>
        </div>

        <div className="score-scale">
          0–39 safe/neutral → 40 suspicious → 80 malicious
        </div>
      </div>
    </div>
  );
}

/* ---------------- URL CARD ---------------- */
function UrlCard({ u }) {
  const [open, setOpen] = useState(false);

  return (
    <li
      className={`list__item ${open ? "open" : ""}`}
      onClick={() => setOpen(!open)}
    >
      <div className="row">
        <div className="row__title">{u.domain || "(unparsed)"}</div>

        <span className={`badge badge--${verdictTone(u.verdict)} badge--right`}>
          {u.verdict}
        </span>
      </div>

      <div className="details">
        <div className="meta"><strong>URL:</strong> {u.url}</div>
        {u.hostname && (
          <div className="meta"><strong>Host:</strong> {u.hostname}</div>
        )}

        {u.notes?.length > 0 && (
          <ul className="notes">
            {u.notes.map((n, i) => <li key={i}>{n}</li>)}
          </ul>
        )}
      </div>
    </li>
  );
}

/* ---------------- APP ---------------- */
function App() {
  const [message, setMessage] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const [howItWorksOpen, setHowItWorksOpen] = useState(false);

  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState(null);

  function showToast(message, type = "warn") {
    setToast({ message, type });
    setTimeout(() => setToast(null), 2600);
  }

  async function analyze() {
    setError(null);
    setResult(null);
    setHowItWorksOpen(false);
    setLoading(true);

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message })
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data?.error || "Request failed");
        setLoading(false);
        return;
      }

      setResult(data);
      setHowItWorksOpen(false);
      setLoading(false);

      if (data.status === "malicious") {
        showToast("Malicious message detected", "bad");
      } else if (data.status === "suspicious") {
        showToast("⚠ Suspicious link detected", "warn");
      } else if (data.status === "neutral") {
        showToast("ℹ Untrusted link (no strong scam signals)", "neutral");
      } else {
        showToast("✔ Scan complete", "good");
      }

    } catch (e) {
      setError(e?.message || "Network error");
      setLoading(false);
    }
  }

  return (
    <div className="app">
      <Toast toast={toast} />

      <h1>Message Scam Checker</h1>

      <textarea
        className="input"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder="Paste the Message here"
      />

      <button
        className="button"
        onClick={analyze}
        disabled={!message.trim() || loading}
      >
        {loading ? "Scanning..." : "Analyze"}
      </button>

      {loading && <Loader />}

      {error && (
        <div className="card card--error">
          <h2>Error</h2>
          <p>{error}</p>
        </div>
      )}

      {result && (
        <div className="card">

          {/* HEADER */}
          <div className="row">
            <h2>Result</h2>

            <span className={`badge badge--${statusTone(result.status)} badge--right`}>
              {result.status}
            </span>
          </div>

          {/* SCORE */}
          <ScoreGauge score={result.score} status={result.status} />

          {/* EXPLANATION */}
          <div className="section explanation">
            <button
              type="button"
              className="section-toggle"
              aria-expanded={howItWorksOpen}
              onClick={() => setHowItWorksOpen((v) => !v)}
            >
              How it works
            </button>

            {howItWorksOpen && (
              <div className="section-toggle__content">
                <p>
                  The system calculates a <strong>risk score (0-100)</strong> based on detected scam signals such as:
                </p>
                <ul>
                  <li>Suspicious or shortened links</li>
                  <li>Domain impersonation or lookalike URLs</li>
                  <li>Urgency or payment-related language</li>
                  <li>Mismatch between brand and domain</li>
                </ul>

                <p>
                  <strong>Score interpretation:</strong>
                </p>
                <ul>
                  <li><strong>0-39:</strong> safe (trusted) or neutral (untrusted)</li>
                  <li><strong>40-79:</strong> suspicious</li>
                  <li><strong>80-100:</strong> malicious</li>
                </ul>

                <p className="muted">
                  Note: A low score does not guarantee safety — only that no strong scam patterns were detected.
                </p>
              </div>
            )}
          </div>

          {/* REASONS */}
          {result.reasons?.length > 0 && (
            <div className="section">
              <h3>Why this rating</h3>
              <ul>
                {result.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
          )}

          {/* THREAT INTEL, CHECK IF THERE IS A MATCH WITH THE LOCAL DATABASE */}
          {result.threatIntel?.checked && (
            <div className="section">
              <h3>Threat intel</h3>
              {Array.isArray(result.threatIntel.dbSources) && result.threatIntel.dbSources.length > 0 && (
                <p>
                  Checked local feeds: {result.threatIntel.dbSources.join(", ")}.
                </p>
              )}
              {result.threatIntel.match ? (
                <p>
                  Match found in local threat-intel database
                  {Array.isArray(result.threatIntel.sources) && result.threatIntel.sources.length > 0
                    ? ` (${result.threatIntel.sources.join(", ")})`
                    : ""}.
                </p>
              ) : (
                <p>No matches found in the local threat-intel database.</p>
              )}
            </div>
          )}

          {/* URLS */}
          {result.urls?.length > 0 && (
            <div className="section">
              <h3>Links found</h3>
              <ul className="list">
                {result.urls.map((u, i) => (
                  <UrlCard key={i} u={u} />
                ))}
              </ul>
            </div>
          )}

        </div>
      )}
    </div>
  );
}

export default App;