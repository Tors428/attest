import { useEffect, useState } from "react";

const API_BASE = "http://127.0.0.1:8000";

type AuditRow = {
  seq: number;
  decision_id: string;
  verdict: string;
  matched_rule_id: string | null;
  policy_version: number;
  latency_ms: number;
  prev_hash_b64: string;
  entry_hash_b64: string;
  signature_b64: string;
  signed_at: string;
  created_at: string;
};

type VerifyResult = {
  entries_checked: number;
  valid: boolean;
  failed_at_seq: number | null;
  failure_reason: string | null;
};

function shortHash(b64: string) {
  return b64.slice(0, 10) + "…";
}

function verdictColor(v: string) {
  if (v === "allow") return "#1f9d55";
  if (v === "block") return "#c81e1e";
  return "#a16207"; // transform
}

export default function App() {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [enforceInput, setEnforceInput] = useState(
    "Tell me a fun fact about octopuses."
  );
  const [enforceBusy, setEnforceBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadAudit() {
    try {
      const res = await fetch(`${API_BASE}/v1/audit?limit=50`);
      if (!res.ok) throw new Error(`audit fetch ${res.status}`);
      setRows(await res.json());
    } catch (e) {
      setError(String(e));
    }
  }

  async function runVerify() {
    setVerifying(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/v1/audit/verify`);
      setVerifyResult(await res.json());
    } catch (e) {
      setError(String(e));
    } finally {
      setVerifying(false);
    }
  }

  async function runEnforce() {
    setEnforceBusy(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/v1/enforce`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          policy_name: "pii_redaction",
          input: enforceInput,
        }),
      });
      if (!res.ok) throw new Error(`enforce ${res.status}`);
      await loadAudit();
    } catch (e) {
      setError(String(e));
    } finally {
      setEnforceBusy(false);
    }
  }

  useEffect(() => {
    loadAudit();
  }, []);

  return (
    <div
      style={{
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        maxWidth: 1100,
        margin: "40px auto",
        padding: "0 24px",
        color: "#111",
      }}
    >
      <header style={{ marginBottom: 32 }}>
        <h1 style={{ margin: 0, fontSize: 28, letterSpacing: -0.5 }}>attest</h1>
        <p style={{ margin: "6px 0 0 0", color: "#666", fontSize: 14 }}>
          policy enforcement gateway · audit log
        </p>
      </header>

      <section style={{ marginBottom: 32 }}>
        <h2 style={{ fontSize: 14, textTransform: "uppercase", color: "#666", letterSpacing: 1 }}>
          run enforce
        </h2>
        <div style={{ display: "flex", gap: 8 }}>
          <input
            value={enforceInput}
            onChange={(e) => setEnforceInput(e.target.value)}
            placeholder="prompt to send to the LLM"
            style={{
              flex: 1,
              padding: "10px 12px",
              fontFamily: "inherit",
              fontSize: 13,
              border: "1px solid #ccc",
              borderRadius: 4,
            }}
          />
          <button
            onClick={runEnforce}
            disabled={enforceBusy}
            style={{
              padding: "10px 16px",
              background: "#111",
              color: "#fff",
              border: "none",
              borderRadius: 4,
              fontFamily: "inherit",
              fontSize: 13,
              cursor: enforceBusy ? "wait" : "pointer",
            }}
          >
            {enforceBusy ? "..." : "enforce"}
          </button>
        </div>
      </section>

      <section style={{ marginBottom: 32 }}>
        <h2 style={{ fontSize: 14, textTransform: "uppercase", color: "#666", letterSpacing: 1 }}>
          chain verification
        </h2>
        <button
          onClick={runVerify}
          disabled={verifying}
          style={{
            padding: "10px 16px",
            background: "#fff",
            border: "1px solid #111",
            borderRadius: 4,
            fontFamily: "inherit",
            fontSize: 13,
            cursor: verifying ? "wait" : "pointer",
          }}
        >
          {verifying ? "verifying..." : "verify chain"}
        </button>
        {verifyResult && (
          <div
            style={{
              marginTop: 12,
              padding: 12,
              border: `1px solid ${verifyResult.valid ? "#1f9d55" : "#c81e1e"}`,
              borderRadius: 4,
              background: verifyResult.valid ? "#f0fdf4" : "#fef2f2",
              fontSize: 13,
            }}
          >
            <strong>{verifyResult.valid ? "valid" : "INVALID"}</strong>{" "}
            · {verifyResult.entries_checked} entries checked
            {!verifyResult.valid && (
              <div style={{ marginTop: 6 }}>
                failed at seq {verifyResult.failed_at_seq}: {verifyResult.failure_reason}
              </div>
            )}
          </div>
        )}
      </section>

      <section>
        <h2 style={{ fontSize: 14, textTransform: "uppercase", color: "#666", letterSpacing: 1 }}>
          recent audit entries
        </h2>
        {error && (
          <div style={{ color: "#c81e1e", marginBottom: 12, fontSize: 13 }}>
            {error}
          </div>
        )}
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ textAlign: "left", borderBottom: "1px solid #ddd" }}>
              <th style={{ padding: "8px 6px" }}>seq</th>
              <th style={{ padding: "8px 6px" }}>verdict</th>
              <th style={{ padding: "8px 6px" }}>matched rule</th>
              <th style={{ padding: "8px 6px" }}>latency</th>
              <th style={{ padding: "8px 6px" }}>entry hash</th>
              <th style={{ padding: "8px 6px" }}>signed at</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.seq} style={{ borderBottom: "1px solid #f0f0f0" }}>
                <td style={{ padding: "8px 6px", color: "#666" }}>{r.seq}</td>
                <td style={{ padding: "8px 6px" }}>
                  <span
                    style={{
                      color: verdictColor(r.verdict),
                      fontWeight: 600,
                    }}
                  >
                    {r.verdict}
                  </span>
                </td>
                <td style={{ padding: "8px 6px" }}>
                  {r.matched_rule_id ?? <span style={{ color: "#999" }}>—</span>}
                </td>
                <td style={{ padding: "8px 6px" }}>{r.latency_ms}ms</td>
                <td style={{ padding: "8px 6px", color: "#666" }}>
                  {shortHash(r.entry_hash_b64)}
                </td>
                <td style={{ padding: "8px 6px", color: "#666" }}>
                  {new Date(r.signed_at).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && (
          <div style={{ color: "#999", fontSize: 13, padding: "20px 0" }}>
            no entries yet — run an enforce above
          </div>
        )}
      </section>
    </div>
  );
}