from prometheus_client import Counter, Histogram

enforce_requests = Counter(
    "attest_enforce_requests_total",
    "Total /v1/enforce requests",
    ["verdict"],
)

enforce_latency_seconds = Histogram(
    "attest_enforce_latency_seconds",
    "End-to-end /v1/enforce latency",
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

llm_latency_seconds = Histogram(
    "attest_llm_latency_seconds",
    "Groq LLM call latency",
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

chain_write_latency_seconds = Histogram(
    "attest_chain_write_latency_seconds",
    "Audit chain write critical section latency",
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25),
)

chain_verify_latency_seconds = Histogram(
    "attest_chain_verify_latency_seconds",
    "Full chain verification latency",
    buckets=(0.001, 0.01, 0.1, 1.0, 5.0, 30.0),
)