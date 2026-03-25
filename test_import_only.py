#!/usr/bin/env python
import sys
import os

# Force immediate output
print("[startup] Python interpreter started", flush=True)
sys.stdout.flush()

print("[startup] Current directory:", os.getcwd(), flush=True)
sys.stdout.flush()

print("[startup] Attempting import dspy...", flush=True)
sys.stdout.flush()

try:
    import dspy
    print("[startup] ✓ dspy imported", flush=True)
    sys.stdout.flush()
except Exception as e:
    print(f"[startup] ✗ dspy import FAILED: {e}", flush=True)
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("[startup] Creating LM instance...", flush=True)
sys.stdout.flush()

try:
    lm = dspy.LM(
        "ollama_chat/llama3",
        api_base="http://localhost:11434",
        api_key="ollama",
        timeout=10,
    )
    print("[startup] ✓ LM instance created", flush=True)
    sys.stdout.flush()
except Exception as e:
    print(f"[startup] ✗ LM creation FAILED: {e}", flush=True)
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("[startup] Configuring DSPy...", flush=True)
sys.stdout.flush()

try:
    dspy.configure(lm=lm)
    print("[startup] ✓ DSPy configured", flush=True)
    sys.stdout.flush()
except Exception as e:
    print(f"[startup] ✗ Configure FAILED: {e}", flush=True)
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("[startup] All initialization complete - SUCCESS", flush=True)
sys.stdout.flush()
