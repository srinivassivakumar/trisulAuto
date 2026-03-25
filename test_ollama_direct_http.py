#!/usr/bin/env python3
"""Test Ollama inference directly without DSPy."""

import json
import urllib.request
import urllib.error

print("[test] Sending direct inference request to Ollama...")

# Simple test prompt
payload = {
    "model": "llama3",
    "prompt": "What is 2+2? Answer in one sentence.",
    "stream": False,
}

try:
    req = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    
    print("[test] Sending request...", flush=True)
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read().decode())
        print(f"\n[SUCCESS] Ollama responded!\n")
        print(f"Response: {result.get('response', 'NO RESPONSE')[:200]}")
        
except urllib.error.URLError as e:
    print(f"[ERROR] Connection failed: {e}")
except Exception as e:
    print(f"[ERROR] {type(e).__name__}: {e}")
