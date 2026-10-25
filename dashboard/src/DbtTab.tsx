import { useEffect, useState, type ReactNode } from "react";

type Run = {
  invocation_id: string;
  started_at: string;
  first_seq: number;
  total: number;
  counts: Record<string, number>;
};

type Node = {
  seq: number;
  unique_id: string;
  resource_type: string | null;
  status: string | null;
  rows: number | null;
  sql_sha256: string | null;
  columns_sha256: string | null;
  verdict: string;
  matched_rule_id: string | null;
  reason: string | null;
  signals: string | null;
  refs: { unique_id: string; seq: number | null }[];
};

type Problem = {
  seq: number;
  label: string;
  reason: string;
  downstream: { seq: number; label: string }[];
};

type FullVerify = { entries_checked: number; valid: boolean; problems: Problem[] };

const h2 = { fontSize: 14, textTransform: "uppercase" as const, color: "#666", letterSpacing: 1 };
const td = { padding: "8px 6px", verticalAlign: "top" as const };
const button = {
  padding: "4px 8px",
  fontFamily: "inherit",
  fontSize: 11,
  border: "1px solid #ccc",
  borderRadius: 4,
  cursor: "pointer",
};

function verdictColor(v: string) {
  if (v === "allow") return "#1f9d55";
  if (v === "block") return "#c81e1e";
  if (v === "flag") return "#7c3aed";
  return "#a16207";
}

// what the verifier found, in words someone outside the data team can act on
function plain(reason: string) {
  if (reason.includes("prev_hash")) return "a record right before this one was deleted or reordered";
  if (reason.includes("signature")) return "the signed record itself was edited";
  return "the stored data was changed after it was signed";
}

function Detail({ n }: { n: Node }) {
  const line = (k: string, v: ReactNode) => (
    <div>
      <span style={{ color: "#666" }}>{k}:</span> {v ?? <span style={{ color: "#999" }}>—</span>}
    </div>
  );
  return (
    <>
      {line("signals", n.signals)}
      {line("status", n.status)}
      {line("rows", n.rows?.toLocaleString())}
      {line("sql sha256", n.sql_sha256)}
      {line("columns sha256", n.columns_sha256)}
      {line(
        "upstream",
        n.refs.length
          ? n.refs.map((r) => `${r.unique_id}${r.seq ? ` (seq ${r.seq})` : ""}`).join(", ")
          : null
      )}
    </>
  );
}

export default function DbtTab({ apiBase }: { apiBase: string }) {
  const [runs, setRuns] = useState<Run[] | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [nodes, setNodes] = useState<Node[] | null>(null);
  const [filter, setFilter] = useState<"all" | "block" | "flag">("all");
  const [open, setOpen] = useState<number | null>(null);
  const [check, setCheck] = useState<FullVerify | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(`${apiBase}/v1/dbt/runs`)
      .then((r) => (r.ok ? r.json() : Promise.reject(`dbt runs ${r.status}`)))
      .then((rows: Run[]) => {
        setRuns(rows);
        if (rows.length) setSelected(rows[0].invocation_id);
      })
      .catch((e) => setError(String(e)));
  }, [apiBase]);

  useEffect(() => {
    if (!selected) return;
    setNodes(null);
    setOpen(null);
    fetch(`${apiBase}/v1/dbt/runs/${selected}`)
      .then((r) => (r.ok ? r.json() : Promise.reject(`dbt run ${r.status}`)))
      .then(setNodes)
      .catch((e) => setError(String(e)));
  }, [apiBase, selected]);

  async function checkTampering() {
    setChecking(true);
    try {
      const res = await fetch(`${apiBase}/v1/audit/verify/full`);
      if (!res.ok) throw new Error(`verify ${res.status}`);
      setCheck(await res.json());
    } catch (e) {
      setError(String(e));
    } finally {
      setChecking(false);
    }
  }

  if (error) return <div style={{ color: "#c81e1e", fontSize: 13 }}>{error}</div>;
  if (!runs) return <div style={{ color: "#999", fontSize: 13 }}>loading…</div>;

  if (!runs.length) {
    return (
      <div style={{ color: "#999", fontSize: 13, padding: "20px 0" }}>
        no dbt runs on the chain yet. run <code>make demo</code> in <code>adapters/dbt/</code>
      </div>
    );
  }

  const run = runs.find((r) => r.invocation_id === selected);
  const c = run?.counts ?? {};
  const tampered = new Set(check?.problems.map((p) => p.seq));
  const affected = new Set(check?.problems.flatMap((p) => p.downstream.map((d) => d.seq)));
  const rows = (nodes ?? []).filter((n) => filter === "all" || n.verdict === filter);

  return (
    <div>
      <section style={{ marginBottom: 24 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 12 }}>
          <h2 style={h2}>dbt runs</h2>
          <select
            value={selected ?? ""}
            onChange={(e) => setSelected(e.target.value)}
            style={{ fontFamily: "inherit", fontSize: 12, padding: 4 }}
          >
            {runs.map((r) => (
              <option key={r.invocation_id} value={r.invocation_id}>
                {new Date(r.started_at).toLocaleString()} · {r.total} nodes ·{" "}
                {r.invocation_id.slice(0, 8)}
              </option>
            ))}
          </select>
        </div>
        <p style={{ fontSize: 13, margin: "4px 0 0 0" }}>
          {run?.total ?? 0} nodes ·{" "}
          <span style={{ color: verdictColor("block") }}>{c.block ?? 0} blocked</span> ·{" "}
          <span style={{ color: verdictColor("flag") }}>{c.flag ?? 0} flagged</span> ·{" "}
          <span style={{ color: verdictColor("allow") }}>{c.allow ?? 0} allowed</span>
        </p>
      </section>

      <section style={{ marginBottom: 24, fontSize: 12 }}>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <button
            onClick={checkTampering}
            disabled={checking}
            style={{ ...button, background: "#fff", cursor: checking ? "wait" : "pointer" }}
          >
            {checking ? "checking..." : "check for tampering"}
          </button>
          {check?.valid && (
            <span style={{ color: "#1f9d55" }}>
              no tampering found in {check.entries_checked.toLocaleString()} records
            </span>
          )}
          {check && !check.valid && (
            <span style={{ color: "#c81e1e" }}>
              {check.problems.length} tampered record{check.problems.length === 1 ? "" : "s"} out of{" "}
              {check.entries_checked.toLocaleString()}
            </span>
          )}
        </div>
        {check?.problems.map((p) => (
          <div key={p.seq} style={{ marginTop: 12, lineHeight: 1.7 }}>
            <div style={{ color: "#c81e1e" }}>
              tampered: {p.label} (seq {p.seq}). {plain(p.reason)}
            </div>
            <div style={{ color: "#999" }}>{p.reason}</div>
            {p.downstream.length > 0 ? (
              <>
                <div style={{ marginTop: 6 }}>
                  built from it, so don't trust these either:
                </div>
                {p.downstream.map((d) => (
                  <div key={d.seq} style={{ paddingLeft: 16 }}>
                    {d.label} (seq {d.seq})
                  </div>
                ))}
              </>
            ) : (
              <div style={{ marginTop: 6 }}>nothing downstream was built from it</div>
            )}
          </div>
        ))}
      </section>

      <section>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
          <h2 style={h2}>nodes</h2>
          <div style={{ display: "flex", gap: 4 }}>
            {(["all", "block", "flag"] as const).map((k) => (
              <button
                key={k}
                onClick={() => setFilter(k)}
                style={{
                  ...button,
                  background: filter === k ? "#111" : "#fff",
                  color: filter === k ? "#fff" : "#111",
                }}
              >
                {k === "all" ? "all" : k === "block" ? "blocked" : "flagged"}
              </button>
            ))}
          </div>
        </div>
        <p style={{ fontSize: 12, color: "#666", margin: "4px 0 12px 0" }}>
          click a row for signals, rows, hashes and upstream
        </p>
        {!nodes && <div style={{ color: "#999", fontSize: 13 }}>loading…</div>}
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ textAlign: "left", borderBottom: "1px solid #ddd" }}>
              <th style={td}>seq</th>
              <th style={td}>node</th>
              <th style={td}>verdict</th>
              <th style={td}>rule</th>
              <th style={td}>why</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((n) => {
              const bad = tampered.has(n.seq) || affected.has(n.seq);
              return [
                <tr
                  key={n.seq}
                  onClick={() => setOpen(open === n.seq ? null : n.seq)}
                  style={{
                    borderBottom: "1px solid #f0f0f0",
                    cursor: "pointer",
                    color: bad ? "#c81e1e" : undefined,
                  }}
                >
                  <td style={{ ...td, color: "#666" }}>{n.seq}</td>
                  <td style={td}>
                    {n.unique_id}
                    {tampered.has(n.seq) && " (tampered)"}
                    {affected.has(n.seq) && !tampered.has(n.seq) && " (built on tampered data)"}
                  </td>
                  <td style={td}>
                    <span style={{ color: verdictColor(n.verdict), fontWeight: 600 }}>{n.verdict}</span>
                  </td>
                  <td style={td}>{n.matched_rule_id ?? <span style={{ color: "#999" }}>—</span>}</td>
                  <td style={{ ...td, color: "#444" }}>{n.matched_rule_id ? n.reason : ""}</td>
                </tr>,
                open === n.seq && (
                  <tr key={`${n.seq}-d`} style={{ background: "#f6f6f6" }}>
                    <td />
                    <td colSpan={4} style={{ ...td, wordBreak: "break-all" }}>
                      <Detail n={n} />
                    </td>
                  </tr>
                ),
              ];
            })}
          </tbody>
        </table>
        {nodes && rows.length === 0 && (
          <div style={{ color: "#999", fontSize: 13, padding: "20px 0" }}>nothing in this category</div>
        )}
      </section>
    </div>
  );
}
