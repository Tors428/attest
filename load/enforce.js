import http from "k6/http";
import { check } from "k6";
import { Trend, Counter } from "k6/metrics";

const BASE_URL = __ENV.ATTEST_URL || "http://127.0.0.1:8000";

// separate metric for chain-write latency, sniffed from the response
const enforceLatency = new Trend("enforce_latency_ms", true);
const verdictCounter = new Counter("verdict_counts");

export const options = {
  scenarios: {
    ramp: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "10s", target: 3 },
        { duration: "30s", target: 3 },
        { duration: "10s", target: 5 },
        { duration: "30s", target: 5 },
        { duration: "10s", target: 8 },
        { duration: "30s", target: 8 },
        { duration: "10s", target: 0 },
      ],
      gracefulStop: "10s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.05"],
    http_req_duration: ["p(95)<10000"],
  },
};

const prompts = [
  "Tell me a fun fact about octopuses.",
  "Explain how a solar panel works in one sentence.",
  "Write a haiku about compilers.",
  "What is the capital of Iceland?",
  "Give me a short recipe for scrambled eggs.",
  "Repeat this exactly: contact@example.com",
  "Say something friendly with the phone number 555-12-3456 in it.",
  "Describe a mountain in ten words.",
];

export default function () {
  const payload = JSON.stringify({
    policy_name: "pii_redaction",
    input: prompts[Math.floor(Math.random() * prompts.length)],
  });

  const params = {
    headers: { "Content-Type": "application/json" },
    timeout: "30s",
  };

  const res = http.post(`${BASE_URL}/v1/enforce`, payload, params);

  check(res, {
    "status is 200": (r) => r.status === 200,
    "has decision_id": (r) => {
      try {
        return JSON.parse(r.body).decision_id !== undefined;
      } catch {
        return false;
      }
    },
  });

  if (res.status === 200) {
    try {
      const body = JSON.parse(res.body);
      enforceLatency.add(body.latency_ms);
      verdictCounter.add(1, { verdict: body.verdict });
    } catch {
      // swallow
    }
  }
}