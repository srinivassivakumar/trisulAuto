#!/usr/bin/env python
import sys
import dspy

print("[test] DSPy/Ollama setup...", flush=True)
lm = dspy.LM(
    "ollama_chat/llama3",
    api_base="http://localhost:11434",
    api_key="ollama",
    timeout=10,
)
dspy.configure(lm=lm)
print("[test] ✓ Setup OK", flush=True)

print("[test] Creating signature...", flush=True)
class SimpleTest(dspy.Signature):
    question: str = dspy.InputField(desc="A question")
    answer: str = dspy.OutputField(desc="A short answer")

predictor = dspy.Predict(SimpleTest)
print("[test] ✓ Signature OK", flush=True)

print("[test] Calling model (timeout=10s)...", flush=True)
sys.stdout.flush()

try:
    import time
    start = time.time()
    result = predictor(question="What is 2+2?")
    elapsed = time.time() - start
    print(f"[test] ✓ Model returned in {elapsed:.1f}s: {result.answer}", flush=True)
except TimeoutError as e:
    elapsed = time.time() - start
    print(f"[test] ✗ Timeout after {elapsed:.1f}s: {e}", flush=True)
except Exception as e:
    elapsed = time.time() - start
    print(f"[test] ✗ Error after {elapsed:.1f}s: {e}", flush=True)
    import traceback
    traceback.print_exc()
