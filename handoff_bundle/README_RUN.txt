Handoff package for Trisul + DSPy + Ollama

How to run (Windows PowerShell):

1) Open PowerShell in this folder
2) Run:
   powershell -ExecutionPolicy Bypass -File .\run_all.ps1 -MaxIps 1 -TimeoutSec 300 -Retries 1 -Model llama3

Notes:
- This script creates .venv, installs Python dependencies, starts 11thstep API,
  runs 14thstepai.py, and then stops the API process.
- If running on CPU-only systems, keep TimeoutSec high (for example 300).
- If GPU is available, you can reduce TimeoutSec significantly.

Optional faster model examples:
-Model phi3:mini
-Model qwen2.5:0.5b
