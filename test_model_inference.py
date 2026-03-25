#!/usr/bin/env python3
"""Test DSPy model inference with realistic inputs."""

import json
import sys

print("[1] Importing dspy...", flush=True)
import dspy

print("[2] Configuring Ollama LM...", flush=True)
lm = dspy.LM(
    "ollama_chat/llama3",
    api_base="http://localhost:11434",
    api_key="ollama",
    timeout=15,
)
dspy.configure(lm=lm)
print("[3] LM configured OK", flush=True)

# Define the signature (same as in main script)
class IPIssueDiagnosis(dspy.Signature):
    """Diagnose network issues."""
    ip_address: str = dspy.InputField(desc="The IP address being diagnosed")
    metrics_json: str = dspy.InputField(desc="JSON object of metrics")
    internal_issues: str = dspy.InputField(desc="Internal-path issues")
    external_issues: str = dspy.InputField(desc="External-path issues")
    top_flows_json: str = dspy.InputField(desc="JSON array of flows")
    infra_context: str = dspy.InputField(desc="Server resource snapshot")
    rule_diagnostics: str = dspy.InputField(desc="Rule engine hints")
    
    priority: str = dspy.OutputField(desc="CRITICAL | HIGH | MEDIUM | LOW")
    problem_category: str = dspy.OutputField(desc="Issue category")
    what_happened: str = dspy.OutputField(desc="What happened (2-3 sentences)")
    where_to_look: str = dspy.OutputField(desc="Where to look")
    where_to_fix: str = dspy.OutputField(desc="Where to fix")

print("[4] Signature defined OK", flush=True)

# Create realistic test inputs
kwargs = {
    "ip_address": "103.174.107.44",
    "metrics_json": json.dumps({
        "Latency Internal (µs)": 5200,
        "Retransmitted Packets External": 342,
        "Retransmission Rate % Internal": 8.5,
        "Poor Quality Flows": 12,
        "Timeouts": 5,
        "Unidirectional Flows": 2,
    }),
    "internal_issues": "High latency, Jitter",
    "external_issues": "Packet retransmissions, Timeouts",
    "top_flows_json": json.dumps([
        {"source": "curltestdata_server_state", "time": "16:00", "tcp_established": 950},
        {"source": "curltestdata_server_state", "time": "16:15", "tcp_established": 1100},
        {"source": "curltestdata_server_state", "time": "16:30", "tcp_established": 880},
    ]),
    "infra_context": "CPU avg=15.8% peak=98.4% | RAM avg=62.9% peak=94.7% | TCP established avg=941.1 | Disk latency avg=0.4ms",
    "rule_diagnostics": "Problem: Congestion\nDiagnostics: High retransmission rate\nFix hints: Check QoS settings",
}

print("[5] Test inputs prepared", flush=True)
print(f"    IP: {kwargs['ip_address']}", flush=True)
print(f"    Metrics count: {len(json.loads(kwargs['metrics_json']))}", flush=True)

print("\n[6] Creating predictor...", flush=True)
predict = dspy.Predict(IPIssueDiagnosis)
print("[7] Predictor created OK", flush=True)

print("\n[8] ===== CALLING MODEL (will block here if Ollama is unresponsive) =====", flush=True)
print("[8] Starting inference on IP 103.174.107.44...", flush=True)

try:
    result = predict(**kwargs)
    print("\n[SUCCESS] Model returned result!", flush=True)
    print(f"\nResult fields:")
    print(f"  priority: {result.priority}")
    print(f"  problem_category: {result.problem_category}")
    print(f"  what_happened: {result.what_happened[:100]}...")
    print(f"  where_to_look: {result.where_to_look[:100]}...")
    print(f"  where_to_fix: {result.where_to_fix[:100]}...")
except TimeoutError as e:
    print(f"\n[TIMEOUT] {e}", flush=True)
    sys.exit(1)
except Exception as e:
    print(f"\n[ERROR] {type(e).__name__}: {e}", flush=True)
    import traceback
    traceback.print_exc()
    sys.exit(1)
