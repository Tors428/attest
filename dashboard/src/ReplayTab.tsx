import { useEffect, useState } from "react";

type Change = {
  seq: number;
  decision_id: string;
  kind: "allow_to_block" | "block_to_allow" | "verdict_changed" | "rule_changed";
  old_verdict: string;
  new_verdict: string;
  old_rule: string | null;
  new_rule: string | null;
  cause_rule: string | null;
  new_reason: string;
};

type Report = {
  generated_at: string;
  range: { from_seq: number; to_seq: number };
  chain: { entries_checked: number; head_entry_hash_b64: string };
  candidate: { policy_name: string; version: number };
  baseline: { versions: Record<string, number> };
  summary: {
    replayed: number;
    unchanged: number;
    changed: number;
    allow_to_block: number;
    block_to_allow: number;
    verdict_changed: number;
    rule_changed: number;
    skipped_no_payload: number;
    baseline_mismatch: number;
  };
  by_rule: Record<string, number>;
  changes: Change[];
  timing: { total_s: number; replay_records_per_sec: number; end_to_end_records_per_sec: number };
};

type Envelope = {
  report: Report;
  signature: { report_sha256_b64: string; signature_b64: string; key_id: string };
};

type ReplaySummary = {
  id: string;
  policy_name: string;
  candidate_version: number;
  from_seq: number;
  to_seq: number;
  created_at: string;
};

type Payload = { input_text: string; raw_output_text: string };

const KIND_LABEL: Record<Change["kind"], string> = {
  allow_to_block: "allowed → blocked",
  block_to_allow: "blocked → allowed",
  verdict_changed: "verdict changed",
  rule_changed: "different rule",
};

const PAGE = 100;

const h2 = { fontSize: 14, textTransform: "uppercase" as const, color: "#666", letterSpacing: 1 };
const td = { padding: "8px 6px", verticalAlign: "top" as const };

function verdictColor(v: string) {
  if (v === "allow") return "#1f9d55";
  if (v === "block") return "#c81e1e";
  return "#a16207";
}

function Stat({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div style={{ flex: 1, padding: 12, border: "1px solid #ddd", borderRadius: 4, background: "#fff" }}>
      <div style={{ fontSize: 22, fontWeight: 600, color: color ?? "#111" }}>
        {value.toLocaleString()}
      </div>
      <div style={{ fontSize: 12, color: "#666", marginTop: 2 }}>{label}</div>
    </div>
  );
}

export default function ReplayTab({ apiBase }: { apiBase: string }) {
  const [list, setList] = useState<ReplaySummary[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [env, setEnv] = useState<Envelope | null>(null);
  const [filter, setFilter] = useState<Change["kind"] | "all">("all");
  const [shown, setShown] = useState(PAGE);
  const [open, setOpen] = useState<Record<string, Payload | "loading" | "missing">>({});
  const [sigCheck, setSigCheck] = useState<{ valid: boolean; reason: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(`${apiBase}/v1/replays`)
      .then((r) => (r.ok ? r.json() : Promise.reject(`replays ${r.status}`)))
      .then((rows: ReplaySummary[]) => {
        setList(rows);
        if (rows.length) setSelected(rows[0].id);
      })
      .catch((e) => setError(String(e)));
  }, [apiBase]);

  useEffect(() => {
    if (!selected) return;
    setEnv(null);
    setSigCheck(null);
    setOpen({});
    setShown(PAGE);
    fetch(`${apiBase}/v1/replays/${selected}`)
      .then((r) => (r.ok ? r.json() : Promise.reject(`replay ${r.status}`)))
      .then(setEnv)
      .catch((e) => setError(String(e)));
  }, [apiBase, selected]);

  async function checkSignature() {
    if (!selected) return;
    const res = await fetch(`${apiBase}/v1/replays/${selected}/verify`);
    setSigCheck(await res.json());
  }

  async function toggle(c: Change) {
    if (open[c.decision_id]) {
      const next = { ...open };
      delete next[c.decision_id];
      setOpen(next);
      return;
    }
    setOpen((o) => ({ ...o, [c.decision_id]: "loading" }));
    const res = await fetch(`${apiBase}/v1/audit/${c.decision_id}/payload`);
    const value = res.ok ? ((await res.json()) as Payload) : "missing";
    setOpen((o) => ({ ...o, [c.decision_id]: value }));
  }

  if (error) return <div style={{ color: "#c81e1e", fontSize: 13 }}>{error}</div>;

  if (!list.length) {
    return (
      <div style={{ color: "#999", fontSize: 13, padding: "20px 0" }}>
        no replays yet. run{" "}
        <code>attest replay --policy policies/pii_redaction_v2.yaml --to 5000</code>
      </div>
    );
  }

  if (!env) return <div style={{ color: "#999", fontSize: 13 }}>loading…</div>;

  const { report, signature } = env;
  const s = report.summary;
  const rows = report.changes.filter((c) => filter === "all" || c.kind === filter);
  const baseline = Object.keys(report.baseline.versions).map((v) => `v${v}`).join(", ");

  return (
    <div>
      <section style={{ marginBottom: 24 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 12 }}>
          <h2 style={h2}>policy replay</h2>
          {list.length > 1 && (
            <select
              value={selected ?? ""}
              onChange={(e) => setSelected(e.target.value)}
              style={{ fontFamily: "inherit", fontSize: 12, padding: 4 }}
            >
              {list.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.policy_name} v{r.candidate_version} · seq {r.from_seq}–{r.to_seq} ·{" "}
                  {new Date(r.created_at).toLocaleString()}
                </option>
              ))}
            </select>
          )}
        </div>
        <p style={{ fontSize: 13, margin: "4px 0 16px 0" }}>
          If <strong>{report.candidate.policy_name} v{report.candidate.version}</strong> had been live
          instead of {baseline}, here's what would have changed across{" "}
          {s.replayed.toLocaleString()} recorded decisions (seq {report.range.from_seq}–{report.range.to_seq}).
        </p>
        <div style={{ display: "flex", gap: 8 }}>
          <Stat label="would now be blocked" value={s.allow_to_block} color="#c81e1e" />
          <Stat label="would now be allowed" value={s.block_to_allow} color="#1f9d55" />
          <Stat label="other changes" value={s.verdict_changed + s.rule_changed} color="#a16207" />
          <Stat label="unchanged" value={s.unchanged} />
        </div>
        {s.baseline_mismatch > 0 && (
          <div style={{ marginTop: 12, fontSize: 13, color: "#c81e1e" }}>
            {s.baseline_mismatch} records no longer reproduce their signed verdict under the old
            policy. treat this diff with care.
          </div>
        )}
      </section>

      <section
        style={{
          marginBottom: 24,
          padding: 12,
          border: "1px solid #ddd",
          borderRadius: 4,
          background: "#fff",
          fontSize: 12,
          color: "#444",
          lineHeight: 1.7,
        }}
      >
        <div>
          chain verified before replay: {report.chain.entries_checked.toLocaleString()} entries, head{" "}
          {report.chain.head_entry_hash_b64.slice(0, 16)}…
        </div>
        <div>
          report signed with ed25519 key {signature.key_id} · sha256{" "}
          {signature.report_sha256_b64.slice(0, 16)}…
        </div>
        <div>
          replayed in {report.timing.total_s}s ({report.timing.end_to_end_records_per_sec.toLocaleString()}{" "}
          records/s end to end) · {new Date(report.generated_at).toLocaleString()}
        </div>
        <div style={{ marginTop: 8, display: "flex", gap: 12, alignItems: "center" }}>
          <button
            onClick={checkSignature}
            style={{
              padding: "6px 12px",
              background: "#fff",
              border: "1px solid #111",
              borderRadius: 4,
              fontFamily: "inherit",
              fontSize: 12,
              cursor: "pointer",
            }}
          >
            verify signature
          </button>
          {sigCheck && (
            <span style={{ color: sigCheck.valid ? "#1f9d55" : "#c81e1e", fontWeight: 600 }}>
              {sigCheck.valid ? "valid" : `INVALID: ${sigCheck.reason}`}
            </span>
          )}
        </div>
      </section>

      {Object.keys(report.by_rule).length > 0 && (
        <section style={{ marginBottom: 24 }}>
          <h2 style={h2}>changes by rule</h2>
          {Object.entries(report.by_rule).map(([rule, n]) => (
            <div key={rule} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, marginBottom: 4 }}>
              <span style={{ width: 180 }}>{rule}</span>
              <div
                style={{
                  height: 10,
                  width: `${Math.max(2, (n / Math.max(s.changed, 1)) * 60)}%`,
                  background: "#111",
                  borderRadius: 2,
                }}
              />
              <span style={{ color: "#666" }}>{n}</span>
            </div>
          ))}
        </section>
      )}

      <section>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
          <h2 style={h2}>flipped decisions</h2>
          <div style={{ display: "flex", gap: 4 }}>
            {(["all", "allow_to_block", "block_to_allow", "verdict_changed", "rule_changed"] as const).map((k) => (
              <button
                key={k}
                onClick={() => {
                  setFilter(k);
                  setShown(PAGE);
                }}
                style={{
                  padding: "4px 8px",
                  fontFamily: "inherit",
                  fontSize: 11,
                  border: "1px solid #ccc",
                  borderRadius: 4,
                  background: filter === k ? "#111" : "#fff",
                  color: filter === k ? "#fff" : "#111",
                  cursor: "pointer",
                }}
              >
                {k === "all" ? "all" : KIND_LABEL[k]}
              </button>
            ))}
          </div>
        </div>
        <p style={{ fontSize: 12, color: "#666", margin: "4px 0 12px 0" }}>
          click a row to see the original prompt and model output
        </p>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ textAlign: "left", borderBottom: "1px solid #ddd" }}>
              <th style={td}>seq</th>
              <th style={td}>change</th>
              <th style={td}>rule</th>
              <th style={td}>why</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, shown).map((c) => {
              const p = open[c.decision_id];
              return [
                <tr
                  key={c.seq}
                  onClick={() => toggle(c)}
                  style={{ borderBottom: "1px solid #f0f0f0", cursor: "pointer" }}
                >
                  <td style={{ ...td, color: "#666" }}>{c.seq}</td>
                  <td style={td}>
                    <span style={{ color: verdictColor(c.old_verdict), fontWeight: 600 }}>{c.old_verdict}</span>
                    {" → "}
                    <span style={{ color: verdictColor(c.new_verdict), fontWeight: 600 }}>{c.new_verdict}</span>
                  </td>
                  <td style={td}>{c.cause_rule ?? <span style={{ color: "#999" }}>default</span>}</td>
                  <td style={{ ...td, color: "#444" }}>{c.new_reason}</td>
                </tr>,
                p && (
                  <tr key={`${c.seq}-p`} style={{ background: "#f6f6f6" }}>
                    <td />
                    <td colSpan={3} style={{ ...td, whiteSpace: "pre-wrap" }}>
                      {p === "loading" && "loading…"}
                      {p === "missing" && <span style={{ color: "#999" }}>payload no longer stored</span>}
                      {typeof p === "object" && (
                        <>
                          <div>
                            <span style={{ color: "#666" }}>prompt:</span> {p.input_text}
                          </div>
                          <div style={{ marginTop: 4 }}>
                            <span style={{ color: "#666" }}>output:</span>{" "}
                            {p.raw_output_text.length > 600
                              ? p.raw_output_text.slice(0, 600) + "…"
                              : p.raw_output_text}
                          </div>
                        </>
                      )}
                    </td>
                  </tr>
                ),
              ];
            })}
          </tbody>
        </table>
        {rows.length === 0 && (
          <div style={{ color: "#999", fontSize: 13, padding: "20px 0" }}>nothing in this category</div>
        )}
        {rows.length > shown && (
          <button
            onClick={() => setShown(shown + PAGE)}
            style={{
              marginTop: 12,
              padding: "6px 12px",
              background: "#fff",
              border: "1px solid #ccc",
              borderRadius: 4,
              fontFamily: "inherit",
              fontSize: 12,
              cursor: "pointer",
            }}
          >
            show more ({rows.length - shown} left)
          </button>
        )}
      </section>
    </div>
  );
}
