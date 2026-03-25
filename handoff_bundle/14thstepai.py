"""
Trisul TCP Network Diagnostic Pipeline — DSPy + Ollama (llama3)

Data priority (real data only, never synthetic tcp-analysis-results.json):
  1. Live Trisul  — import 11thstep.py and call its ZMQ functions directly
  2. 11thstep API — http://127.0.0.1:8080/api/ip_flows  (if --mode serve_api running)
  3. Fallback     — curltestdata.txt TCP state timeline when API is not running

Infra context is always parsed from the real curltestdata.txt hour-long curl dump.
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import dspy

# ── Constants ────────────────────────────────────────────────────────────────

WORKSPACE = Path(__file__).parent
CURL_JSON = WORKSPACE / "curltestdata.json"
CURL_DATA = WORKSPACE / "curltestdata.txt"
STEP11 = WORKSPACE / "11thstep.py"
GROUP_GUID = "{E45623ED-744C-4053-1401-84C72EE49D3B}"
API_BASE = os.getenv("TRISUL_API_BASE", "http://127.0.0.1:8080")
IST = timezone(timedelta(hours=5, minutes=30))
LAST_CURL_SOURCE = "unknown"
LAST_CURL_ERROR = ""
DIAGNOSE_TIMEOUT_SEC = int(os.getenv("DIAGNOSE_TIMEOUT_SEC", "90"))
DIAGNOSE_RETRIES = int(os.getenv("DIAGNOSE_RETRIES", "2"))
LM_TIMEOUT_SEC = int(os.getenv("LM_TIMEOUT_SEC", "45"))
MAX_IPS = int(os.getenv("MAX_IPS", "5"))


# ── DSPy Signatures ───────────────────────────────────────────────────────────

class IPIssueDiagnosis(dspy.Signature):
    """
    You are a senior network operations engineer with deep expertise in TCP/IP
    troubleshooting.  Given real TCP analyzer metrics for a single IP address,
    diagnose the root cause, and produce concrete, actionable guidance.
    Be specific: name network layers, device types, and CLI commands where relevant.
    """

    ip_address: str = dspy.InputField(
        desc="The IP address being diagnosed"
    )
    metrics_json: str = dspy.InputField(
        desc=(
            "JSON object of metric name → measured value for this IP.  "
            "Keys are full metric names such as 'Latency Internal (µs)', "
            "'Retransmitted Packets External', 'Retransmission Rate % Internal', "
            "'Poor Quality Flows', 'Timeouts', 'Unidirectional Flows'."
        )
    )
    internal_issues: str = dspy.InputField(
        desc="Comma-separated list of internal-path (LAN/DC-side) issues detected"
    )
    external_issues: str = dspy.InputField(
        desc="Comma-separated list of external-path (WAN/Internet-side) issues detected"
    )
    top_flows_json: str = dspy.InputField(
        desc=(
            "JSON array of the 5 worst flows for this IP (from API), OR 5 "
            "representative server TCP state snapshots from curltestdata.txt "
            "(when API is not running).  Each entry has a 'source' field to "
            "indicate which kind of data it is."
        )
    )
    infra_context: str = dspy.InputField(
        desc=(
            "Real server resource snapshot from the last hour: "
            "CPU% avg/peak/latest, RAM% avg/peak/latest, TCP established avg/peak/latest, "
            "TCP time_wait avg/peak/latest, disk latency avg/peak/latest, "
            "interface bandwidth in/out"
        )
    )
    rule_diagnostics: str = dspy.InputField(
        desc=(
            "Pre-computed diagnostic hints from the deterministic rule engine.  "
            "Empty string if no rule matched.  Use as supporting evidence only."
        )
    )

    priority: str = dspy.OutputField(
        desc="CRITICAL | HIGH | MEDIUM | LOW  — based on the magnitude of the metrics"
    )
    problem_category: str = dspy.OutputField(
        desc=(
            "One of: Congestion, Packet_Loss, Asymmetric_Routing, Firewall_Drop, "
            "Hardware_Failure, Overloaded_Server, Timeout_Cascade, Mixed"
        )
    )
    what_happened: str = dspy.OutputField(
        desc=(
            "2–3 sentence explanation of exactly what is happening at the network "
            "level for this IP based on the measured metrics"
        )
    )
    where_to_look: str = dspy.OutputField(
        desc=(
            "Bullet list of specific inspection points: switch/router layer, "
            "firewall session table, interface error counters, routing table, NIC stats"
        )
    )
    where_to_fix: str = dspy.OutputField(
        desc=(
            "Ordered action list with concrete remediation steps: "
            "specific CLI commands, config changes, or hardware actions"
        )
    )


class IncidentSummary(dspy.Signature):
    """
    You are a senior network architect producing an executive incident report.
    Consolidate per-IP findings into a prioritized, grouped remediation plan.
    """

    diagnoses_json: str = dspy.InputField(
        desc=(
            "JSON array of per-IP diagnosis objects — each containing: "
            "ip, priority, problem_category, what_happened, where_to_look, where_to_fix"
        )
    )
    observation_window: str = dspy.InputField(
        desc="Human-readable time window covered, e.g. '2026-03-19 03:20 to 04:20 IST'"
    )

    critical_ips: str = dspy.OutputField(
        desc=(
            "CRITICAL and HIGH priority IPs needing immediate action.  "
            "Format: '• <IP> — <one-line reason>' per line"
        )
    )
    grouped_fix_plan: str = dspy.OutputField(
        desc=(
            "Remediation steps grouped by network area:\n"
            "1) Physical / Link Layer\n"
            "2) Firewall / NAT / Stateful devices\n"
            "3) Routing / Path asymmetry\n"
            "4) Capacity / QoS\n"
            "5) Host / Application"
        )
    )
    top_priority_action: str = dspy.OutputField(
        desc="Single most impactful action to execute RIGHT NOW to reduce harm"
    )


# ── Ollama Configuration ──────────────────────────────────────────────────────

def configure_ollama_lm() -> None:
    model_name = os.getenv("OLLAMA_MODEL", "llama3")
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    lm = dspy.LM(
        f"ollama_chat/{model_name}",
        api_base=base_url,
        api_key="ollama",
        timeout=LM_TIMEOUT_SEC,
    )
    dspy.configure(lm=lm)


# ── Real Data Source 1: Live Trisul via 11thstep module ──────────────────────

def _load_11thstep_module():
    """Import 11thstep.py as a module.  Returns module or None."""
    if not STEP11.exists():
        print("[warn] 11thstep.py not found")
        return None
    spec = importlib.util.spec_from_file_location("trisul_analyzer", STEP11)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        print(f"[warn] Could not load 11thstep.py: {exc}")
        return None
    return mod


def load_live_trisul_data() -> Optional[dict]:
    """
    Primary data source.  Imports 11thstep.py, checks Trisul connectivity,
    then calls the real ZMQ counter functions to collect per-IP issue data
    for the last hour.  Returns None if Trisul is unreachable.
    """
    mod = _load_11thstep_module()
    if mod is None:
        return None

    if not mod.check_trisul_connection():
        print("[info] Trisul not reachable — will try API fallback")
        return None

    print("[info] Connected to Trisul — fetching live counter data …")
    try:
        rules = mod.load_rules()
        to_ts = int(time.time())
        from_ts = to_ts - 3600

        meter_labels, _, _ = mod.fetch_counter_group_info(GROUP_GUID)

        meter_results = {}
        for meter in sorted(meter_labels.keys()):
            meter_results[meter] = mod.fetch_topper_keys(
                GROUP_GUID, meter, from_ts, to_ts, maxitems=5
            )

        suspect_ip_to_key: dict = {}
        for entries in meter_results.values():
            for item in entries:
                suspect_ip_to_key.setdefault(item["ip"], item["key"])

        ip_to_meter_values: dict = {}
        ip_to_meters: dict = {}
        for ip, trisul_key in suspect_ip_to_key.items():
            all_vals = mod.fetch_counter_item_all_meters(
                GROUP_GUID, trisul_key, from_ts, to_ts
            )
            filtered = {m: v for m, v in all_vals.items() if m in meter_labels}
            ip_to_meter_values[ip] = filtered
            ip_to_meters[ip] = {m for m, v in filtered.items() if v > 0}

        ip_records = []
        for ip in suspect_ip_to_key:
            ip_meters = ip_to_meters.get(ip, set())
            if not ip_meters:
                continue

            metrics: dict = {}
            metrics_set: set = set()
            internal_issues: list = []
            external_issues: list = []

            for m in sorted(ip_meters):
                label = meter_labels.get(m, f"Meter {m}")
                val = ip_to_meter_values[ip].get(m, 0)
                metrics[label] = mod.convert_to_milliseconds(m, val)
                if m in mod.METER_TO_METRIC:
                    metrics_set.add(mod.METER_TO_METRIC[m])
                if m in mod.INTERNAL_SET:
                    internal_issues.append(label)
                if m in mod.EXTERNAL_SET:
                    external_issues.append(label)

            rule = mod.find_matching_rule(sorted(metrics_set), rules)
            ip_records.append({
                "ip": ip,
                "classification": mod.classify_issue(ip_meters),
                "internal_issues": internal_issues,
                "external_issues": external_issues,
                "values": metrics,
                "rule": rule,
            })

        print(f"[info] Collected data for {len(ip_records)} IPs from Trisul")
        return {
            "source": "trisul_live",
            "from_ts": from_ts,
            "to_ts": to_ts,
            "ips": ip_records,
        }

    except Exception as exc:
        print(f"[warn] Error collecting Trisul data: {exc}")
        return None


# ── Real Data Source 2: Live 11thstep HTTP API ───────────────────────────────

def _api_get(path: str, timeout: int = 5) -> Optional[dict | list]:
    """Simple HTTP GET against the 11thstep API.  Returns parsed JSON or None."""
    try:
        with urllib.request.urlopen(f"{API_BASE}{path}", timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, json.JSONDecodeError):
        return None


def is_api_running() -> bool:
    """Return True if the 11thstep API is reachable."""
    result = _api_get("/api/ip_flows?ip=probe", timeout=3)
    return result is not None


# ── Shared: parse curltestdata.txt into record list ──────────────────────────

def _parse_curl_data() -> list:
    """
    Parse curltestdata.txt (JSON array of per-minute server snapshots) into a
    Python list.  Supports both a top-level JSON array and newline-delimited JSON.
    Returns [] on any error so callers can safely iterate.
    """
    global LAST_CURL_SOURCE, LAST_CURL_ERROR
    candidates = [CURL_JSON, CURL_DATA]
    errors = []

    for source in candidates:
        if not source.exists():
            continue

        try:
            raw = source.read_text(encoding="utf-8-sig")
        except OSError as exc:
            errors.append(f"{source.name}: read error: {exc}")
            continue

        stripped = raw.strip()
        if not stripped:
            errors.append(f"{source.name}: empty file")
            continue

        # First attempt: full JSON document.
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                if isinstance(parsed.get("message"), list):
                    LAST_CURL_SOURCE = source.name
                    return parsed["message"]
                LAST_CURL_SOURCE = source.name
                return [parsed]
            if isinstance(parsed, list):
                LAST_CURL_SOURCE = source.name
                return parsed
        except json.JSONDecodeError as exc:
            errors.append(f"{source.name}: JSON parse error at line {exc.lineno}, col {exc.colno}: {exc.msg}")

        # Second attempt: newline-delimited JSON records.
        records = []
        for ln in stripped.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                item = json.loads(ln)
                if isinstance(item, dict) and isinstance(item.get("message"), list):
                    records.extend(item["message"])
                else:
                    records.append(item)
            except json.JSONDecodeError:
                continue

        if records:
            LAST_CURL_SOURCE = source.name
            return records

        errors.append(f"{source.name}: no parseable NDJSON records")

    LAST_CURL_SOURCE = "none"
    LAST_CURL_ERROR = " | ".join(errors[-4:]) if errors else "No curl dataset files found"
    return []


def _run_predictor_in_subprocess(predictor, kwargs, timeout_sec: int) -> Optional[dict]:
    """
    Run DSPy predictor call in subprocess with hard timeout.
    If timeout_sec is exceeded, subprocess is forcibly killed.
    Returns result dict on success, None on timeout, raises on error.
    """
    import tempfile
    
    # Serialize input/output through temp files
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        input_file = f.name
        json.dump({'predictor_config': 'skip_for_now', 'kwargs': kwargs}, f)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        output_file = f.name
    
    # Build subprocess script (note: simple approach avoids complex escaping)
    script_lines = [
        "import sys",
        "import json",
        f"sys.path.insert(0, r'{WORKSPACE}')",
        "",
        "import importlib.util",
        f"spec = importlib.util.spec_from_file_location('main', r'{WORKSPACE / '14thstepai.py'}')",
        "main_mod = importlib.util.module_from_spec(spec)",
        "spec.loader.exec_module(main_mod)",
        "",
        "with open(r'" + input_file + "') as f:",
        "    data = json.load(f)",
        "",
        "kwargs = data['kwargs']",
        "",
        "main_mod.configure_ollama_lm()",
        "predictor = main_mod.dspy.Predict(main_mod.IPIssueDiagnosis)",
        "result = predictor(**kwargs)",
        "",
        "output = {",
        "    'priority': result.priority,",
        "    'problem_category': result.problem_category,",
        "    'what_happened': result.what_happened,",
        "    'where_to_look': result.where_to_look,",
        "    'where_to_fix': result.where_to_fix,",
        "}",
        "with open(r'" + output_file + "', 'w') as f:",
        "    json.dump(output, f)",
    ]
    script = '\n'.join(script_lines)
    
    try:
        proc = subprocess.Popen(
            [sys.executable, '-c', script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        
        try:
            stdout, stderr = proc.communicate(timeout=timeout_sec)
            
            # Try to read output file
            if not os.path.exists(output_file):
                if stderr:
                    print(f"  [subprocess error] {stderr[:200]}")
                return None
            
            with open(output_file) as f:
                result_dict = json.load(f)
            
            # Cleanup temp files
            try:
                os.unlink(input_file)
                os.unlink(output_file)
            except:
                pass
                
            return result_dict
            
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
            # Cleanup temp files
            try:
                os.unlink(input_file)
                os.unlink(output_file)
            except:
                pass
            raise TimeoutError(f"prediction exceeded {timeout_sec}s timeout -- Ollama likely blocked")
            
    except TimeoutError:
        raise
    except Exception as exc:
        try:
            os.unlink(input_file)
            os.unlink(output_file)
        except:
            pass
        raise RuntimeError(f"subprocess error: {exc}")


def _predict_with_timeout_retry(predictor, kwargs, timeout_sec, retries):
    """
    Run predictor with retries using subprocess-based hard timeout.
    Each IP diagnosis runs in an isolated subprocess that will be killed if it
    exceeds timeout_sec. This prevents Ollama blocking from freezing the pipeline.
    """
    last_error = None

    for attempt in range(1, retries + 1):
        start = time.time()
        try:
            result_dict = _run_predictor_in_subprocess(predictor, kwargs, timeout_sec)
            
            elapsed = time.time() - start
            if elapsed > timeout_sec * 0.8:
                print(f"  [warn] call took {elapsed:.1f}s (target {timeout_sec}s)")
            
            if result_dict:
                # Convert dict to object with attributes
                result = type('DXResult', (), result_dict)()
                return result
            else:
                raise RuntimeError("no output from subprocess")
                
        except TimeoutError as exc:
            last_error = str(exc)
            elapsed = time.time() - start
            print(f"  [warn] attempt {attempt}/{retries} timed out after {elapsed:.1f}s: Ollama blocked")
        except Exception as exc:
            last_error = str(exc)
            print(f"  [warn] attempt {attempt}/{retries} failed: {exc}")

    raise RuntimeError(last_error or "prediction failed after all retries")


# ── Fallback flow data: TCP state timeline from curltestdata.txt ─────────────

def load_flows_from_curl_data(ip: str) -> list:
    """
    Fallback used when the 11thstep API is not running.
    curltestdata.txt has no per-IP flows, but it has per-minute server-wide
    TCP connection state (established / time_wait / listen counts) and interface
    metrics.  This function turns those into 5 representative timeline rows so
    Ollama receives real temporal evidence about connection surges, TIME_WAIT
    buildup, and interface bandwidth — clearly labelled as server-wide data.
    """
    records = _parse_curl_data()
    if not records:
        return [{"note": "curl dataset unavailable or empty"}]

    rows = []
    for rec in records:
        try:
            tcp   = rec.get("tcp_connection") or {}
            iface = ((rec.get("interface") or [{}])[0])
            cpu_pct = (rec.get("cpu") or {}).get("percent_used", "?")
            ram_pct = (rec.get("ram") or {}).get("percent_used", "?")
            disk_lat = (
                ((rec.get("disk_io_summary") or {})
                 .get("latency_data") or {})
                .get("latency", "?")
            )
            rows.append({
                "source": "curltestdata_server_state",
                "time": tcp.get("time", "?"),
                "tcp_established":      tcp.get("established", "?"),
                "tcp_time_wait":        tcp.get("time_wait",   "?"),
                "tcp_listen":           tcp.get("listen",      "?"),
                "in_bandwidth_bps":     iface.get("in_bandwidth",  "?"),
                "out_bandwidth_bps":    iface.get("out_bandwidth", "?"),
                "interface_in_errors":  iface.get("inErr",  "0"),
                "interface_out_errors": iface.get("outErr", "0"),
                "cpu_pct":       cpu_pct,
                "ram_pct":       ram_pct,
                "disk_latency_ms": disk_lat,
            })
        except Exception:
            pass

    # Pick 5 evenly distributed samples: first, Q1, mid, Q3, last
    n = len(rows)
    if n == 0:
        return [{"note": "no parseable records in curl dataset"}]
    if n <= 5:
        return rows
    indices = [0, n // 4, n // 2, (3 * n) // 4, n - 1]
    return [rows[i] for i in indices]


def load_flows_from_api(ip: str) -> list:
    """
    Preferred: fetch top flow issues for one IP from the running 11thstep API.
    Fallback:  if API is not running, parse curltestdata.txt for real server
               TCP connection state and interface metrics as proxy evidence.
    """
    result = _api_get(f"/api/ip_flows?ip={ip}&include_infra=false")
    if isinstance(result, list) and result:
        return result
    # API not running or returned empty — use local curl dataset instead
    flows = load_flows_from_curl_data(ip)
    if LAST_CURL_SOURCE == "none":
        print(
            f"    [fallback] API not running and curl parse failed for {ip}. "
            f"Reason: {LAST_CURL_ERROR}"
        )
    else:
        print(f"    [fallback] API not running — using {LAST_CURL_SOURCE} for {ip}")
    return flows


# ── Infra Context: summary stats from curltestdata.txt ───────────────────────

def load_infra_context() -> str:
    """
    Return a compact string with real avg / peak / latest stats for every key
    metric extracted from the hourly curltestdata.txt dump.
    """
    records = _parse_curl_data()
    if not records:
        return (
            "Infrastructure data unavailable (curl dataset missing or unreadable). "
            f"Last parse error: {LAST_CURL_ERROR}"
        )

    cpu_pct, ram_pct, tcp_est, tcp_tw, disk_lat_ms, bw_in, bw_out = (
        [], [], [], [], [], [], []
    )
    for rec in records:
        try:
            cpu_pct.append(float(rec["cpu"]["percent_used"]))
        except (KeyError, TypeError, ValueError):
            pass
        try:
            ram_pct.append(float(rec["ram"]["percent_used"]))
        except (KeyError, TypeError, ValueError):
            pass
        try:
            tcp_est.append(int(rec["tcp_connection"]["established"]))
        except (KeyError, TypeError, ValueError):
            pass
        try:
            tcp_tw.append(int(rec["tcp_connection"]["time_wait"]))
        except (KeyError, TypeError, ValueError):
            pass
        try:
            disk_lat_ms.append(
                float(rec["disk_io_summary"]["latency_data"]["latency"])
            )
        except (KeyError, TypeError, ValueError):
            pass
        try:
            ifaces = rec.get("interface") or []
            if ifaces:
                bw_in.append(float(ifaces[0]["in_bandwidth"]))
                bw_out.append(float(ifaces[0]["out_bandwidth"]))
        except (KeyError, TypeError, ValueError, IndexError):
            pass

    def stat(vals: list, unit: str = "") -> str:
        if not vals:
            return "n/a"
        return (
            f"avg={sum(vals)/len(vals):.1f}{unit} "
            f"peak={max(vals):.1f}{unit} "
            f"latest={vals[-1]:.1f}{unit}"
        )

    parts = [
        f"Samples: {len(records)} (~1 h)",
        f"CPU%: {stat(cpu_pct, '%')}",
        f"RAM%: {stat(ram_pct, '%')}",
        f"TCP established: {stat([float(v) for v in tcp_est])}",
        f"TCP time_wait: {stat([float(v) for v in tcp_tw])}",
        f"Disk latency: {stat(disk_lat_ms, ' ms')}",
    ]
    if bw_in:
        parts.append(f"Interface in_bw: {stat(bw_in, ' bps')}")
    if bw_out:
        parts.append(f"Interface out_bw: {stat(bw_out, ' bps')}")

    return f"Source: {LAST_CURL_SOURCE}  |  " + "  |  ".join(parts)


# ── Pipeline ──────────────────────────────────────────────────────────────────

def run_pipeline() -> None:
    configure_ollama_lm()

    print("=" * 72)
    print("Trisul TCP Network Diagnostic Pipeline  (DSPy + Ollama llama3)")
    print("=" * 72)

    # ── Step 1: Acquire real IP issue data ──
    data = load_live_trisul_data()

    if data is None:
        print("[info] Checking for 11thstep API at", API_BASE, "…")
        if is_api_running():
            print("[info] API is up — IP list must be provided via Trisul live pull.")
            print("[error] Trisul is unreachable and API has no IP-list endpoint.")
            print(
                "  Options:\n"
                "  • Ensure Trisul is running at 10.193.2.9:12001\n"
                "  • Or run:  python 11thstep.py --mode report_with_api\n"
                "    then re-run this script"
            )
        else:
            print(
                "[error] Neither Trisul nor the 11thstep API is reachable.\n"
                "  • Start Trisul at 10.193.2.9:12001, or\n"
                "  • Run:  python 11thstep.py --mode serve_api"
            )
        return

    ip_records = data.get("ips", [])
    if MAX_IPS > 0:
        ip_records = ip_records[:MAX_IPS]
    from_ts: int = data.get("from_ts", int(time.time()) - 3600)
    to_ts: int = data.get("to_ts", int(time.time()))

    if not ip_records:
        print("[warn] No IPs with active TCP issues found in the last hour.")
        return

    obs_window = (
        f"{datetime.fromtimestamp(from_ts, tz=IST).strftime('%Y-%m-%d %H:%M')} to "
        f"{datetime.fromtimestamp(to_ts,   tz=IST).strftime('%Y-%m-%d %H:%M')} IST"
    )

    # ── Step 2: Load real infra context ──
    infra_ctx = load_infra_context()

    print(f"\n[window]  {obs_window}")
    print(f"[infra]   {infra_ctx}")
    print(f"[IPs]     {len(ip_records)} IPs with issues found\n")
    print(f"[limit]   MAX_IPS={MAX_IPS} (set 0 for all)\n")
    if LAST_CURL_SOURCE == "none":
        print("[warn] curl fallback data is unavailable; diagnosis will proceed without infra timeline context.")
        print(f"[warn] curl parse detail: {LAST_CURL_ERROR}\n")

    # ── Step 3: Per-IP diagnosis via DSPy ──
    diagnose = dspy.Predict(IPIssueDiagnosis)
    diagnoses = []

    for record in ip_records:
        ip: str = record["ip"]
        print(f"  Diagnosing {ip} ...")

        # API first; curltestdata.txt fallback if API not running
        flows = load_flows_from_api(ip)
        flows_json = json.dumps(flows[:5] if len(flows) > 5 else flows)

        rule = record.get("rule") or {}
        rule_text = ""
        if rule:
            rule_text = (
                f"Problem: {rule.get('problem', '')}\n"
                "Diagnostics: " + "; ".join(rule.get("diagnostics", [])) + "\n"
                "Fix hints: " + "; ".join(rule.get("fix", []))
            )

        try:
            result = _predict_with_timeout_retry(
                predictor=diagnose,
                kwargs={
                    "ip_address": ip,
                    "metrics_json": json.dumps(record.get("values", {})),
                    "internal_issues": ", ".join(record.get("internal_issues", [])) or "none",
                    "external_issues": ", ".join(record.get("external_issues", [])) or "none",
                    "top_flows_json": flows_json,
                    "infra_context": infra_ctx,
                    "rule_diagnostics": rule_text or "none",
                },
                timeout_sec=DIAGNOSE_TIMEOUT_SEC,
                retries=DIAGNOSE_RETRIES,
            )
            diag = {
                "ip": ip,
                "priority": result.priority,
                "problem_category": result.problem_category,
                "what_happened": result.what_happened,
                "where_to_look": result.where_to_look,
                "where_to_fix": result.where_to_fix,
            }
            diagnoses.append(diag)
            print(f"    -> [{diag['priority']}] {diag['problem_category']}")
        except Exception as exc:
            print(f"    -> ERROR: {exc}")

    if not diagnoses:
        print("\n[warn] No diagnoses generated.")
        return

    # ── Step 4: Overall incident summary via DSPy ──
    print("\n[info] Generating incident summary …")
    summarize = dspy.Predict(IncidentSummary)
    summary = None
    try:
        summary = summarize(
            diagnoses_json=json.dumps(diagnoses, indent=2),
            observation_window=obs_window,
        )
    except Exception as exc:
        print(f"[warn] Summary generation failed: {exc}")

    # ── Step 5: Print structured results ──
    print("\n" + "=" * 72)
    print("PER-IP DIAGNOSIS")
    print("=" * 72)
    for d in diagnoses:
        print(f"\n{'─' * 60}")
        print(f"IP              : {d['ip']}")
        print(f"Priority        : {d['priority']}")
        print(f"Category        : {d['problem_category']}")
        print(f"\nWhat happened\n  {d['what_happened']}")
        print(f"\nWhere to look\n  {d['where_to_look']}")
        print(f"\nWhere to fix\n  {d['where_to_fix']}")

    if summary:
        print("\n" + "=" * 72)
        print("INCIDENT SUMMARY")
        print("=" * 72)
        print(f"\nCritical / High Priority IPs:\n{summary.critical_ips}")
        print(f"\nGrouped Fix Plan:\n{summary.grouped_fix_plan}")
        print(f"\n>>> TOP ACTION RIGHT NOW:\n  {summary.top_priority_action}")

    print("\n" + "=" * 72)


if __name__ == "__main__":
    run_pipeline()