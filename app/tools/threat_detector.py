import concurrent.futures
import json
import os
import time
from urllib.parse import unquote

try:
    from google import genai
except ImportError:
    genai = None

GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
MODEL_NAME = os.getenv("ASA_DETECTION_MODEL", "gemini-2.5-flash")
HEURISTICS_ENABLED = os.getenv("ASA_ENABLE_HEURISTICS", "true").lower() == "true"
LLM_MAX_ATTEMPTS = int(os.getenv("ASA_LLM_MAX_ATTEMPTS", "2"))

if genai is not None and GEMINI_API_KEY:
    client = genai.Client(api_key=GEMINI_API_KEY)
else:
    client = None

SEVERITY_WEIGHT = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}

ALLOWED_TYPES = [
    "SQL Injection",
    "XSS",
    "Brute Force",
    "Path Traversal",
    "Unknown",
    "None",
]

ALLOWED_SEVERITY = ["LOW", "MEDIUM", "HIGH"]


def is_safe_mode():
    return os.getenv("ASA_MODE", "HYBRID").upper() == "SAFE"


def is_llm_enabled() -> bool:
    return (not is_safe_mode()) and client is not None


def normalize_signal(signal: str) -> str:
    return signal.lower().strip().replace('"', "'")


def canonicalize_signal(signal: str) -> str:
    normalized = normalize_signal(unquote(signal))
    for token in ["/**/", "%2f%2a%2a%2f", "%252f%252a%252a%252f", "\t", "\n", "\r"]:
        normalized = normalized.replace(token, "")
    return normalized


def compute_risk(confidence: float, severity: str) -> float:
    weight = SEVERITY_WEIGHT.get(severity, 1)
    return round(confidence * weight, 2)


def validate_llm_output(obj: dict) -> dict:
    try:
        threat_type = obj.get("type", "Unknown")
        confidence = float(obj.get("confidence", 0.3))
        severity = obj.get("severity", "LOW")

        if threat_type not in ALLOWED_TYPES:
            threat_type = "Unknown"

        if severity not in ALLOWED_SEVERITY:
            severity = "LOW"

        confidence = max(0.0, min(confidence, 1.0))

        return {
            "type": threat_type,
            "confidence": confidence,
            "severity": severity,
            "reason": obj.get("reason", "LLM classification"),
        }
    except Exception:
        return {
            "type": "Unknown",
            "confidence": 0.3,
            "severity": "LOW",
            "reason": "Invalid LLM output",
        }


def heuristic_detect(signal: str) -> dict | None:
    if not HEURISTICS_ENABLED:
        return None

    s = canonicalize_signal(signal)

    if any(
        pattern in s
        for pattern in [
            "or '1'='1",
            "or 1=1",
            "or1=1",
            "union select",
            "unionselect",
            "drop table",
            "'--",
            "sleep(",
            "benchmark(",
            "xp_cmdshell",
        ]
    ):
        return {
            "type": "SQL Injection",
            "confidence": 0.95,
            "severity": "HIGH",
            "detection_mode": "deterministic",
            "reason_source": "heuristic_rule",
            "reason": "Detected SQL injection pattern",
        }

    if "<script>" in s or "javascript:" in s or "onerror=" in s or "onload=" in s:
        return {
            "type": "XSS",
            "confidence": 0.90,
            "severity": "HIGH",
            "detection_mode": "deterministic",
            "reason_source": "heuristic_rule",
            "reason": "Detected script injection pattern",
        }

    if "../" in s or "..\\" in s:
        return {
            "type": "Path Traversal",
            "confidence": 0.92,
            "severity": "HIGH",
            "detection_mode": "deterministic",
            "reason_source": "heuristic_rule",
            "reason": "Detected path traversal pattern",
        }

    if "login failed" in s or "invalid password" in s:
        return {
            "type": "Brute Force",
            "confidence": 0.85,
            "severity": "MEDIUM",
            "detection_mode": "deterministic",
            "reason_source": "heuristic_rule",
            "reason": "Repeated login failure pattern",
        }

    return None


def _generate_with_genai(prompt: str):
    return client.models.generate_content(model=MODEL_NAME, contents=prompt)


def detect_threat(signal: str) -> dict:
    h = heuristic_detect(signal)
    if h:
        h["confidence_source"] = "heuristic"
        h["fallback_triggered"] = False
        h["risk_score"] = compute_risk(h["confidence"], h["severity"])
        return h

    if is_safe_mode() or client is None:
        return {
            "type": "None" if is_safe_mode() else "Unknown",
            "confidence": 0.0 if is_safe_mode() else 0.3,
            "severity": "LOW",
            "risk_score": 0.0 if is_safe_mode() else compute_risk(0.3, "LOW"),
            "detection_mode": "deterministic" if is_safe_mode() else "fallback",
            "confidence_source": "heuristic" if is_safe_mode() else "fallback",
            "fallback_triggered": False if is_safe_mode() else True,
            "reason_source": "safe_mode" if is_safe_mode() else "system_fallback",
            "reason": "SAFE mode: no threat detected" if is_safe_mode() else "LLM package unavailable -> fallback applied",
        }

    prompt = f"""
    Analyze this security log and classify threat.
    Return JSON:
    {{
      "type": "...",
      "confidence": 0-1,
      "severity": "LOW|MEDIUM|HIGH",
      "reason": "..."
    }}

    Log: {signal}
    """

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        for attempt in range(1, LLM_MAX_ATTEMPTS + 1):
            future = executor.submit(_generate_with_genai, prompt)
            try:
                response = future.result(timeout=5.0)
                txt = (response.text or "").strip().replace("```json", "").replace("```", "")
                raw_obj = json.loads(txt)
                obj = validate_llm_output(raw_obj)
                obj["detection_mode"] = "llm-assisted"
                obj["confidence_source"] = "llm"
                obj["fallback_triggered"] = False
                obj["reason_source"] = "llm_untrusted"
                obj["prompt_version"] = "threat-detector-v2"
                obj["model_name"] = MODEL_NAME
                obj["llm_attempt"] = attempt
                obj["risk_score"] = compute_risk(obj["confidence"], obj["severity"])
                return obj
            except Exception:
                future.cancel()
                if attempt < LLM_MAX_ATTEMPTS:
                    time.sleep(0.2 * attempt)
                    continue
                return {
                    "type": "Unknown",
                    "confidence": 0.3,
                    "severity": "LOW",
                    "risk_score": compute_risk(0.3, "LOW"),
                    "detection_mode": "fallback",
                    "confidence_source": "fallback",
                    "fallback_triggered": True,
                    "reason_source": "system_fallback",
                    "reason": "LLM failure -> fallback applied",
                }
