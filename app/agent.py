import inspect
import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from threading import Lock

from dotenv import load_dotenv

from app.storage import (
    create_action,
    create_agent_run,
    create_event,
    create_incident,
    create_task,
    get_incident,
    list_actions,
    list_agent_runs,
    list_recent_incidents,
    list_tasks,
    complete_task,
    update_incident,
)
from app.tools.decision_engine import decision_engine
from app.tools.log_analyzer import analyze_logs
from app.tools.mitigation import mitigate
from app.tools.patch_generator import generate_remediation
from app.tools.threat_detector import compute_risk, detect_threat

load_dotenv()

for proxy_key in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
    proxy_value = os.getenv(proxy_key, "")
    if "127.0.0.1:9" in proxy_value:
        os.environ.pop(proxy_key, None)

try:
    from google.adk.agents import Agent as AdkAgent
except ImportError:
    try:
        from google.adk.agents import LlmAgent as AdkAgent
    except ImportError:
        AdkAgent = None

try:
    from google.adk.runners import Runner
    from google.adk.sessions import InMemorySessionService
    from google.genai import types
except ImportError:
    Runner = None
    InMemorySessionService = None
    types = None


SYSTEM_NAME = "Multi-Agent Security Operations Assistant"
SYSTEM_SHORT_NAME = "MSOA"
ADK_APP_NAME = "msoa_coordinator"
ADK_USER_ID = "msoa_demo_user"
ADK_MODEL = os.getenv("ASA_ADK_MODEL", "gemini-2.5-flash")
ADK_AVAILABLE = all([AdkAgent, Runner, InMemorySessionService, types])
ADK_EXECUTION_ENABLED = os.getenv("ASA_ENABLE_ADK_ADVISORY", "true").lower() == "true"
ADK_CACHE_TTL_SECONDS = int(os.getenv("ASA_ADK_CACHE_TTL_SECONDS", "120"))
ENABLE_ESCALATION = os.getenv("ASA_ENABLE_ESCALATION", "true").lower() == "true"

ALLOWED_TYPES = ["SQL Injection", "XSS", "Brute Force", "Path Traversal", "Unknown", "None"]
ALLOWED_MODES = ["deterministic", "llm-assisted", "fallback"]
SEVERITY_WEIGHT = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
CONFIDENCE_BUCKETS = {
    "VERY_HIGH": 0.9,
    "HIGH": 0.78,
    "MEDIUM": 0.58,
    "LOW": 0.35,
}
ESCALATION_WEIGHTS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

attack_memory = {}
attack_memory_lock = Lock()
MEMORY_TTL_SECONDS = 3600
adk_cache_lock = Lock()
adk_response_cache = {}


@dataclass
class ExecutionContext:
    request_id: str
    incident_id: str
    request_type: str
    raw_input: str
    normalized_input: str
    user_id: str = "demo"
    session_id: str | None = None
    source: str = "assistant_api"
    analysis: dict = field(default_factory=dict)
    classification: dict = field(default_factory=dict)
    decision: dict = field(default_factory=dict)
    actions: list = field(default_factory=list)
    tasks: list = field(default_factory=list)
    agent_messages: list = field(default_factory=list)
    artifacts: dict = field(default_factory=dict)
    trace: dict = field(default_factory=dict)
    plan: list = field(default_factory=list)
    agent_results: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


def validate_schema(obj: dict) -> dict:
    try:
        if obj.get("type") not in ALLOWED_TYPES:
            obj["type"] = "Unknown"

        assert isinstance(obj.get("confidence"), (int, float)), "Confidence must be numerical"
        assert obj.get("severity") in ["LOW", "MEDIUM", "HIGH"], "Invalid severity level"
        assert obj.get("detection_mode") in ALLOWED_MODES, f"Invalid mode: {obj.get('detection_mode')}"

        obj["confidence"] = max(0.0, min(1.0, float(obj["confidence"])))
        obj["raw_confidence"] = obj["confidence"]
        bucket, calibrated_confidence = calibrate_confidence(obj)
        obj["confidence_bucket"] = bucket
        obj["confidence"] = calibrated_confidence
        obj["confidence_semantics"] = "relative_rank_not_probability"

        if "risk_score" not in obj or obj.get("risk_score") == 0.0:
            obj["risk_score"] = round(obj["confidence"] * SEVERITY_WEIGHT.get(obj["severity"], 1), 2)

        return obj
    except Exception as exc:
        return {
            "type": "Unknown",
            "confidence": 0.0,
            "severity": "LOW",
            "risk_score": 0.0,
            "detection_mode": "fallback",
            "reason": f"Validator Error: {exc}",
        }


def update_events(ip: str, now: float, severity: str = "LOW", threat_type: str = "Unknown") -> dict:
    with attack_memory_lock:
        _cleanup_memory_locked(now)
        memory = attack_memory.setdefault(
            ip,
            {
                "events": [],
                "event_records": [],
                "applied_actions": set(),
                "last_seen": 0.0,
            },
        )
        memory["events"].append(now)
        memory["event_records"].append({"ts": now, "severity": severity, "threat_type": threat_type})
        memory["events"] = [event_ts for event_ts in memory["events"] if now - event_ts <= 60]
        memory["event_records"] = [event for event in memory["event_records"] if now - event["ts"] <= 60]
        memory["last_seen"] = now
        return _snapshot_memory_locked(memory)


def register_applied_actions(ip: str, action_keys: list[str], now: float) -> dict:
    with attack_memory_lock:
        _cleanup_memory_locked(now)
        memory = attack_memory.setdefault(
            ip,
            {
                "events": [],
                "event_records": [],
                "applied_actions": set(),
                "last_seen": 0.0,
            },
        )
        memory["applied_actions"].update(action_keys)
        memory["last_seen"] = now
        return _snapshot_memory_locked(memory)


def get_memory_snapshot(ip: str, now: float | None = None) -> dict:
    with attack_memory_lock:
        if now is None:
            now = time.time()
        _cleanup_memory_locked(now)
        memory = attack_memory.setdefault(
            ip,
            {
                "events": [],
                "event_records": [],
                "applied_actions": set(),
                "last_seen": 0.0,
            },
        )
        return _snapshot_memory_locked(memory)


def _cleanup_memory_locked(now: float) -> None:
    stale_ips = [ip for ip, data in attack_memory.items() if now - data.get("last_seen", 0.0) > MEMORY_TTL_SECONDS]
    for ip in stale_ips:
        attack_memory.pop(ip, None)


def _snapshot_memory_locked(memory: dict) -> dict:
    return {
        "events": list(memory["events"]),
        "event_records": [dict(event) for event in memory.get("event_records", [])],
        "applied_actions": set(memory["applied_actions"]),
        "last_seen": memory["last_seen"],
    }


def calibrate_confidence(obj: dict) -> tuple[str, float]:
    raw_confidence = max(0.0, min(1.0, float(obj.get("confidence", 0.0))))
    detection_mode = obj.get("detection_mode", "fallback")
    reason_source = obj.get("reason_source", "")

    if detection_mode == "deterministic" and reason_source == "heuristic_rule":
        if raw_confidence >= 0.9:
            return "VERY_HIGH", CONFIDENCE_BUCKETS["VERY_HIGH"]
        return "HIGH", CONFIDENCE_BUCKETS["HIGH"]
    if detection_mode == "llm-assisted":
        if raw_confidence >= 0.8:
            return "HIGH", CONFIDENCE_BUCKETS["HIGH"]
        if raw_confidence >= 0.55:
            return "MEDIUM", CONFIDENCE_BUCKETS["MEDIUM"]
        return "LOW", CONFIDENCE_BUCKETS["LOW"]
    if detection_mode == "fallback":
        return "LOW", CONFIDENCE_BUCKETS["LOW"]
    if raw_confidence == 0.0:
        return "LOW", 0.0
    return "MEDIUM", CONFIDENCE_BUCKETS["MEDIUM"]


def evaluate_escalation(memory: dict) -> dict:
    events_15s = [event for event in memory.get("event_records", []) if memory["last_seen"] - event["ts"] <= 15]
    events_60s = memory.get("event_records", [])
    weighted_score = sum(ESCALATION_WEIGHTS.get(event["severity"], 1) for event in events_60s)
    burst_active = len(events_15s) >= 3
    sustained_active = len(events_60s) >= 5 and weighted_score >= 9
    status = burst_active or sustained_active

    if burst_active:
        profile = "burst"
        reason = f"Burst escalation: {len(events_15s)} events in 15s"
    elif sustained_active:
        profile = "sustained"
        reason = f"Sustained escalation: weighted score {weighted_score} across {len(events_60s)} events in 60s"
    else:
        profile = "normal"
        reason = f"Below escalation thresholds ({len(events_15s)} events in 15s, weighted score {weighted_score} in 60s)"

    return {
        "status": status,
        "profile": profile,
        "events_15s": len(events_15s),
        "events_60s": len(events_60s),
        "weighted_score_60s": weighted_score,
        "reason": reason,
    }


def build_threat_snapshot(log_text: str) -> dict:
    analyzed = analyze_logs(log_text)
    threat = validate_schema(detect_threat(analyzed["payload"]))
    threat_type = threat.get("type", "Unknown")
    return {
        "analysis": analyzed,
        "classification": {
            "type": threat_type,
            "threat_type": threat_type,
            "behavior": threat.get("behavior", "Single Event"),
            "severity": threat.get("severity", "LOW"),
            "confidence": threat.get("confidence", 0.0),
            "raw_confidence": threat.get("raw_confidence", threat.get("confidence", 0.0)),
            "confidence_bucket": threat.get("confidence_bucket", "LOW"),
            "confidence_semantics": threat.get("confidence_semantics", "relative_rank_not_probability"),
            "risk_score": threat.get("risk_score", 0.0),
            "detection_mode": threat.get("detection_mode", "fallback"),
            "deterministic_match": threat.get("detection_mode") == "deterministic",
            "reason_source": threat.get("reason_source", "system_fallback"),
            "prompt_version": threat.get("prompt_version"),
            "model_name": threat.get("model_name"),
            "reason": threat.get("reason", "No reason provided"),
        },
    }


def plan_workflow_tool(request_type: str, request_summary: str = "", confidence_bucket: str = "", proposed_decision: str = "") -> dict:
    if request_type == "log_triage":
        steps = [
            {"agent": "CoordinatorAgent", "step": "plan", "purpose": "Decompose the incident workflow"},
            {"agent": "DetectionAgent", "step": "detect", "purpose": "Normalize log and classify threat"},
            {"agent": "RiskAgent", "step": "assess", "purpose": "Evaluate risk, escalation, and decision"},
            {"agent": "MitigationAgent", "step": "act", "purpose": "Apply mitigation and create analyst tasks"},
            {"agent": "AuditAgent", "step": "record", "purpose": "Persist collaboration and explainability"},
        ]
    elif request_type == "incident_followup":
        steps = [
            {"agent": "CoordinatorAgent", "step": "plan", "purpose": "Interpret follow-up request"},
            {"agent": "RiskAgent", "step": "review", "purpose": "Assess whether further action is needed"},
            {"agent": "MitigationAgent", "step": "task", "purpose": "Create or update analyst follow-up tasks"},
            {"agent": "AuditAgent", "step": "record", "purpose": "Persist the follow-up decision"},
        ]
    else:
        steps = [
            {"agent": "CoordinatorAgent", "step": "plan", "purpose": "Interpret task command"},
            {"agent": "MitigationAgent", "step": "task", "purpose": "Execute task tool action"},
            {"agent": "AuditAgent", "step": "record", "purpose": "Persist task operation"},
        ]

    return {
        "request_type": request_type,
        "summary": request_summary or "No summary provided",
        "confidence_bucket": confidence_bucket,
        "proposed_decision": proposed_decision,
        "steps": steps,
    }


class TaskManagerTool:
    def create_task(self, title: str, description: str, incident_id: str | None = None, priority: str = "MEDIUM", owner: str = "analyst", source_agent: str = "CoordinatorAgent") -> dict:
        return create_task(
            title=title,
            description=description,
            incident_id=incident_id,
            priority=priority,
            owner=owner,
            source_agent=source_agent,
            metadata={"tool": "TaskManagerTool"},
        )

    def list_tasks(self, incident_id: str | None = None, status: str | None = None) -> list[dict]:
        return list_tasks(incident_id=incident_id, status=status)

    def complete_task(self, task_id: str) -> dict | None:
        return complete_task(task_id)


task_manager_tool = TaskManagerTool()


def create_followup_task_tool(title: str, details: str, incident_id: str = "", priority: str = "MEDIUM") -> dict:
    return task_manager_tool.create_task(
        title=title,
        description=details,
        incident_id=incident_id or None,
        priority=priority,
        source_agent="ADKCoordinator",
    )


def list_open_tasks_tool(incident_id: str = "") -> list[dict]:
    return task_manager_tool.list_tasks(incident_id=incident_id or None, status="OPEN")


def incident_snapshot_tool(incident_id: str) -> dict:
    return {
        "incident": get_incident(incident_id),
        "tasks": list_tasks(incident_id=incident_id),
        "actions": list_actions(incident_id=incident_id),
        "agent_runs": list_agent_runs(incident_id=incident_id),
    }


def analyze_security_log(log_text: str) -> dict:
    snapshot = build_threat_snapshot(log_text)
    classification = snapshot["classification"]
    remediation = generate_remediation(classification["type"])
    summary = f"{classification['type']} detected with risk {classification['risk_score']}" if classification["type"] != "None" else "No threat detected"
    return {
        "summary": summary,
        "analysis": snapshot["analysis"],
        "classification": classification,
        "remediation": remediation,
    }


root_agent = None
session_service = None
runner = None

if ADK_AVAILABLE:
    root_agent = AdkAgent(
        name=ADK_APP_NAME,
        model=ADK_MODEL,
        description="Coordinator agent for the Multi-Agent Security Operations Assistant.",
        instruction=(
            "You are the coordinator for a multi-agent security operations assistant. "
            "Use plan_workflow_tool to inspect workflow steps, use analyze_security_log for threat context, "
            "and use task tools when follow-up work is needed. "
            "When asked for a recommendation, return valid JSON with keys: summary, coordinator_plan, "
            "recommended_decision, follow_up_task, reason, runtime. "
            "Only recommend decision overrides for low-confidence or fallback cases."
        ),
        tools=[
            plan_workflow_tool,
            analyze_security_log,
            create_followup_task_tool,
            list_open_tasks_tool,
            incident_snapshot_tool,
        ],
    )
    session_service = InMemorySessionService()
    runner = Runner(agent=root_agent, app_name=ADK_APP_NAME, session_service=session_service)


class ASAAgent:
    @staticmethod
    def _get_cache_key(prompt: str, cache_context: dict | None = None) -> str:
        return json.dumps({"prompt": prompt.strip(), "cache_context": cache_context or {}}, sort_keys=True)

    @staticmethod
    def _extract_retry_after_seconds(error_text: str) -> int | None:
        retry_match = re.search(r"retry in ([0-9]+(?:\.[0-9]+)?)s", error_text, re.IGNORECASE)
        if retry_match:
            return max(1, int(float(retry_match.group(1))))
        delay_match = re.search(r"'retryDelay': '([0-9]+)s'", error_text)
        if delay_match:
            return max(1, int(delay_match.group(1)))
        return None

    def _get_cached_response(self, prompt: str, cache_context: dict | None = None) -> dict | None:
        now = time.time()
        cache_key = self._get_cache_key(prompt, cache_context)
        with adk_cache_lock:
            expired = [key for key, value in adk_response_cache.items() if value["expires_at"] <= now]
            for key in expired:
                adk_response_cache.pop(key, None)
            cached = adk_response_cache.get(cache_key)
            if not cached:
                return None
            return json.loads(json.dumps(cached["result"]))

    def _cache_response(self, prompt: str, result: dict, cache_context: dict | None = None, ttl_seconds: int | None = None) -> None:
        cache_key = self._get_cache_key(prompt, cache_context)
        with adk_cache_lock:
            adk_response_cache[cache_key] = {
                "expires_at": time.time() + (ttl_seconds or ADK_CACHE_TTL_SECONDS),
                "result": result,
            }

    @staticmethod
    async def _maybe_await(value):
        if inspect.isawaitable(value):
            return await value
        return value

    @staticmethod
    def _extract_text_from_event(event) -> str:
        content = getattr(event, "content", None)
        parts = getattr(content, "parts", None) or []
        texts = [part.text for part in parts if getattr(part, "text", None)]
        return "\n".join(texts).strip()

    @staticmethod
    def _parse_response_text(text: str):
        if not text:
            return {}
        cleaned = text.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return {"response_text": text}

    async def run(self, prompt: str, cache_context: dict | None = None) -> dict:
        cached_result = self._get_cached_response(prompt, cache_context)
        if cached_result is not None:
            cached_result["cache_hit"] = True
            return cached_result

        if ADK_EXECUTION_ENABLED and ADK_AVAILABLE and runner and session_service and root_agent:
            session_id = f"msoa-{uuid.uuid4()}"
            try:
                await self._maybe_await(
                    session_service.create_session(
                        app_name=ADK_APP_NAME,
                        user_id=ADK_USER_ID,
                        session_id=session_id,
                    )
                )
                message = types.Content(role="user", parts=[types.Part(text=prompt)])
                final_text = ""
                events = runner.run_async(user_id=ADK_USER_ID, session_id=session_id, new_message=message)

                async for event in events:
                    text = self._extract_text_from_event(event)
                    if text:
                        final_text = text
                    is_final = getattr(event, "is_final_response", None)
                    if callable(is_final) and is_final() and text:
                        final_text = text

                result = {
                    "agent": "msoa_coordinator_adk",
                    "agent_interface": "google_adk_runner",
                    "runtime": "google_adk",
                    "adk_status": "ok",
                    "cache_hit": False,
                    "root_agent": ADK_APP_NAME,
                    "session_id": session_id,
                    "input": prompt,
                    "response": self._parse_response_text(final_text),
                    "response_text": final_text,
                }
                self._cache_response(prompt, result, cache_context=cache_context)
                return result
            except Exception as exc:
                snapshot = build_threat_snapshot(prompt)
                error_text = str(exc)
                retry_after_seconds = self._extract_retry_after_seconds(error_text)
                result = {
                    "agent": "msoa_coordinator_adk",
                    "agent_interface": "google_adk_runner",
                    "runtime": "google_adk",
                    "adk_status": "error",
                    "cache_hit": False,
                    "root_agent": ADK_APP_NAME,
                    "session_id": session_id,
                    "input": prompt,
                    "adk_error": error_text,
                    "retry_after_seconds": retry_after_seconds,
                    "fallback_response": {
                        "summary": "ADK unavailable, using deterministic coordinator path.",
                        "classification": snapshot["classification"],
                        "analysis": snapshot["analysis"],
                    },
                }
                error_ttl = min(ADK_CACHE_TTL_SECONDS, retry_after_seconds) if retry_after_seconds else 15
                self._cache_response(prompt, result, cache_context=cache_context, ttl_seconds=error_ttl)
                return result

        snapshot = build_threat_snapshot(prompt)
        return {
            "agent": "msoa_coordinator_adk",
            "agent_interface": "fallback_wrapper",
            "runtime": "fallback_wrapper",
            "adk_available": False,
            "input": prompt,
            "analysis": snapshot["analysis"],
            "classification": snapshot["classification"],
        }


asa_agent = ASAAgent()


class BaseRoleAgent:
    name = "BaseAgent"

    def _record(self, context: ExecutionContext, step_name: str, status: str, input_payload: dict | None, output_payload: dict | None, message: str, handoff_to: str | None = None) -> dict:
        run_id = create_agent_run(
            incident_id=context.incident_id,
            request_id=context.request_id,
            agent_name=self.name,
            step_name=step_name,
            status=status,
            input_payload=input_payload,
            output_payload=output_payload,
            message=message,
        )
        entry = {
            "run_id": run_id,
            "agent": self.name,
            "step": step_name,
            "status": status,
            "message": message,
            "handoff_to": handoff_to,
            "timestamp": time.time(),
        }
        context.agent_messages.append(entry)
        context.agent_results[self.name] = {
            "status": status,
            "step": step_name,
            "message": message,
            "output": output_payload or {},
        }
        return entry


class DetectionAgent(BaseRoleAgent):
    name = "DetectionAgent"

    async def run(self, context: ExecutionContext) -> dict:
        analysis = analyze_logs(context.normalized_input)
        classification = validate_schema(detect_threat(analysis["payload"]))
        threat_type = classification.get("type", "Unknown")
        base_risk_score = compute_risk(classification["confidence"], classification["severity"])

        classification["threat_type"] = threat_type
        classification["behavior"] = classification.get("behavior", "Single Event")
        classification["deterministic_match"] = classification.get("detection_mode") == "deterministic"
        classification["base_risk_score"] = base_risk_score
        classification["effective_risk_score"] = base_risk_score
        classification["risk_score"] = base_risk_score
        classification["risk_breakdown"] = {
            "confidence": classification["confidence"],
            "severity_weight": SEVERITY_WEIGHT.get(classification["severity"], 1),
            "base_result": base_risk_score,
            "formula": "confidence x severity_weight",
            "result": base_risk_score,
        }
        analysis["source"] = context.source

        event_id = create_event(
            context.incident_id,
            context.request_id,
            context.raw_input,
            context.normalized_input,
            context.source,
            analysis,
        )
        context.analysis = analysis
        context.classification = classification
        context.artifacts["event_id"] = event_id
        context.trace["detection"] = {
            "analysis": analysis,
            "classification": classification,
            "event_id": event_id,
        }
        self._record(
            context,
            step_name="detect",
            status="COMPLETED",
            input_payload={"raw_input": context.raw_input},
            output_payload={"analysis": analysis, "classification": classification, "event_id": event_id},
            message=f"Analyzed log and classified threat as {threat_type}.",
            handoff_to="RiskAgent",
        )
        return {"analysis": analysis, "classification": classification, "event_id": event_id}


class RiskAgent(BaseRoleAgent):
    name = "RiskAgent"

    async def run(self, context: ExecutionContext) -> dict:
        if not context.classification or "severity" not in context.classification:
            incident = get_incident(context.incident_id) or {}
            saved_analysis, saved_classification = restore_incident_snapshot(incident)
            if context.request_type == "incident_followup" and saved_classification.get("severity"):
                context.analysis = context.analysis or saved_analysis or {
                    "ip": incident.get("source_ip") or "unknown",
                    "path": "/followup",
                    "method": "NOTE",
                    "payload": context.raw_input,
                    "source": context.source,
                }
                context.analysis["source"] = context.source
                context.classification = saved_classification
                context.classification["reason"] = (
                    f"{context.classification.get('reason', 'Stored incident classification reused')}"
                    " | Reused original incident classification for follow-up."
                )
                context.classification["reason_source"] = "incident_snapshot_reuse"
                context.classification.setdefault("threat_type", context.classification.get("type", incident.get("threat_type") or "Unknown"))
                context.classification.setdefault("type", context.classification.get("threat_type", "Unknown"))
                context.classification.setdefault("base_risk_score", compute_risk(context.classification.get("confidence", 0.0), context.classification.get("severity", "LOW")))
                context.classification.setdefault("effective_risk_score", context.classification.get("risk_score", context.classification["base_risk_score"]))
                context.classification.setdefault(
                    "risk_breakdown",
                    {
                        "confidence": context.classification.get("confidence", 0.0),
                        "severity_weight": SEVERITY_WEIGHT.get(context.classification.get("severity", "LOW"), 1),
                        "base_result": context.classification.get("base_risk_score", 0.0),
                        "formula": "reused_incident_snapshot",
                        "result": context.classification.get("risk_score", 0.0),
                    },
                )
            else:
                threat_type = incident.get("threat_type") or "Unknown"
                context.analysis = context.analysis or {
                    "ip": incident.get("source_ip") or "unknown",
                    "path": "/followup",
                    "method": "NOTE",
                    "payload": context.raw_input,
                    "source": context.source,
                }
                context.classification = {
                    "type": threat_type,
                    "threat_type": threat_type,
                    "behavior": "Follow Up",
                    "severity": "LOW",
                    "confidence": CONFIDENCE_BUCKETS["MEDIUM"],
                    "raw_confidence": CONFIDENCE_BUCKETS["MEDIUM"],
                    "confidence_bucket": "MEDIUM",
                    "confidence_semantics": "relative_rank_not_probability",
                    "base_risk_score": compute_risk(CONFIDENCE_BUCKETS["MEDIUM"], "LOW"),
                    "effective_risk_score": compute_risk(CONFIDENCE_BUCKETS["MEDIUM"], "LOW"),
                    "risk_score": compute_risk(CONFIDENCE_BUCKETS["MEDIUM"], "LOW"),
                    "risk_breakdown": {
                        "confidence": CONFIDENCE_BUCKETS["MEDIUM"],
                        "severity_weight": 1,
                        "base_result": compute_risk(CONFIDENCE_BUCKETS["MEDIUM"], "LOW"),
                        "formula": "followup_default",
                        "result": compute_risk(CONFIDENCE_BUCKETS["MEDIUM"], "LOW"),
                    },
                    "detection_mode": "fallback",
                    "deterministic_match": False,
                    "reason_source": "incident_followup",
                    "reason": "Incident follow-up requested by analyst.",
                }

        source_ip = context.analysis.get("ip", "unknown")
        memory = update_events(
            source_ip,
            time.time(),
            severity=context.classification["severity"],
            threat_type=context.classification["threat_type"],
        )
        escalation = evaluate_escalation(memory) if ENABLE_ESCALATION else {
            "status": False,
            "profile": "disabled",
            "events_15s": 0,
            "events_60s": len(memory["events"]),
            "weighted_score_60s": 0,
            "reason": "Escalation disabled by feature flag.",
        }

        if escalation["status"]:
            context.classification["behavior"] = "Aggressive Attacker"
            context.classification["effective_risk_score"] = 3.0
            context.classification["risk_score"] = 3.0
            context.classification["risk_breakdown"]["formula"] = "escalation_override"
            context.classification["risk_breakdown"]["result"] = 3.0
            context.classification["reason"] += " | ESCALATION OVERRIDE APPLIED"

        decision = decision_engine(context.classification, escalated=escalation["status"])
        decision["decision_confidence"] = context.classification["confidence"]
        decision["decision_source"] = "DeterministicAgents"
        decision["decision_authority"] = "deterministic_pipeline"
        decision["decision_thresholds"] = {
            "execute": float(os.getenv("ASA_EXECUTE_THRESHOLD", "2.5")),
            "observe": float(os.getenv("ASA_OBSERVE_THRESHOLD", "1.5")),
        }
        decision["adk_review"] = {
            "status": "skipped",
            "recommended_decision": None,
            "reason": "High-confidence deterministic result kept authoritative.",
            "influenced_outcome": False,
            "eligible_for_override": False,
        }

        if context.classification.get("confidence_bucket") in {"LOW", "MEDIUM"} or context.classification.get("detection_mode") == "fallback":
            decision["adk_review"] = await self._review_with_adk(context, decision)
            if decision["adk_review"].get("override_ready"):
                decision["decision"] = decision["adk_review"]["recommended_decision"]
                decision["decision_reason"] = f"ADK coordinator override: {decision['adk_review']['reason']}"
                decision["adk_review"]["influenced_outcome"] = True
                decision["adk_review"]["final_decision"] = decision["decision"]
                decision["decision_source"] = "ADKCoordinator"
                decision["decision_authority"] = "llm_override"

        decision["decision_trace"] = [
            f"detection_mode = {context.classification['detection_mode']}",
            f"confidence_bucket = {context.classification['confidence_bucket']}",
            f"base_risk = {context.classification['base_risk_score']}",
            f"effective_risk = {context.classification['risk_score']}",
            f"escalation_active = {escalation['status']}",
            f"adk_influenced = {decision['adk_review']['influenced_outcome']}",
            f"decision_source = {decision['decision_source']}",
            f"decision = {decision['decision']}",
        ]

        context.decision = decision
        context.artifacts["memory"] = {
            "events_last_60s": len(memory["events"]),
            "applied_actions": sorted(memory["applied_actions"]),
        }
        context.trace["risk"] = {
            "decision": decision,
            "escalation": escalation,
            "memory": {
                "events_last_60s": len(memory["events"]),
                "applied_actions_count": len(memory["applied_actions"]),
            },
        }
        self._record(
            context,
            step_name="assess",
            status="COMPLETED",
            input_payload={"classification": context.classification},
            output_payload={"decision": decision, "escalation": escalation},
            message=f"Evaluated risk and produced decision {decision['decision']}.",
            handoff_to="MitigationAgent",
        )
        return {"decision": decision, "escalation": escalation, "memory": memory}

    async def _review_with_adk(self, context: ExecutionContext, current_decision: dict) -> dict:
        prompt = json.dumps(
            {
                "system": SYSTEM_NAME,
                "task": "Review low-confidence security triage decision",
                "request_type": context.request_type,
                "incident_id": context.incident_id,
                "analysis": context.analysis,
                "classification": context.classification,
                "current_decision": current_decision,
                "instructions": {
                    "allowed_decisions": ["EXECUTE", "OBSERVE", "IGNORE"],
                    "only_override_for_low_confidence_or_fallback": True,
                },
            },
            ensure_ascii=True,
            sort_keys=True,
        )
        adk_raw = await asa_agent.run(
            prompt,
            cache_context={
                "surface": "risk_review",
                "incident_id": context.incident_id,
                "confidence_bucket": context.classification.get("confidence_bucket"),
            },
        )
        response = adk_raw.get("response") or {}
        recommended = response.get("recommended_decision")
        influenced = False
        reason = response.get("reason") or adk_raw.get("adk_error") or "ADK review completed."
        original_decision = current_decision.get("decision")
        eligible_for_override = context.classification.get("confidence_bucket") in {"LOW", "MEDIUM"} or context.classification.get("detection_mode") == "fallback"

        override_ready = recommended in {"EXECUTE", "OBSERVE", "IGNORE"} and eligible_for_override

        if response.get("follow_up_task"):
            follow_up = response["follow_up_task"]
            if isinstance(follow_up, dict) and follow_up.get("title"):
                created = task_manager_tool.create_task(
                    title=follow_up["title"],
                    description=follow_up.get("details", "Coordinator-requested follow-up"),
                    incident_id=context.incident_id,
                    priority=follow_up.get("priority", "MEDIUM"),
                    source_agent="ADKCoordinator",
                )
                context.tasks.append(created)

        return {
            "status": adk_raw.get("adk_status", "fallback"),
            "recommended_decision": recommended,
            "original_decision": original_decision,
            "final_decision": recommended if override_ready else current_decision.get("decision"),
            "reason": reason,
            "influenced_outcome": influenced,
            "eligible_for_override": eligible_for_override,
            "override_ready": override_ready,
            "runtime": adk_raw.get("runtime"),
        }


class MitigationAgent(BaseRoleAgent):
    name = "MitigationAgent"

    async def run(self, context: ExecutionContext) -> dict:
        results = {"actions": [], "tasks": []}

        if context.request_type == "task_command":
            command = context.metadata.get("task_command", {})
            action = command.get("action", "list")
            if action == "create":
                created = task_manager_tool.create_task(
                    title=command.get("title", "Untitled task"),
                    description=command.get("description", "Created from task command"),
                    incident_id=command.get("incident_id") or context.incident_id,
                    priority=command.get("priority", "MEDIUM"),
                    source_agent=self.name,
                )
                context.tasks.append(created)
                results["tasks"].append(created)
                message = "Created task via TaskManagerTool."
            elif action == "complete":
                completed = task_manager_tool.complete_task(command.get("task_id", ""))
                if completed:
                    context.tasks.append(completed)
                    results["tasks"].append(completed)
                message = "Completed task via TaskManagerTool."
            else:
                listed = task_manager_tool.list_tasks(incident_id=command.get("incident_id"), status=command.get("status"))
                context.tasks.extend([task for task in listed if task not in context.tasks])
                results["tasks"] = listed
                message = "Listed tasks via TaskManagerTool."

            self._record(
                context,
                step_name="task",
                status="COMPLETED",
                input_payload=command,
                output_payload=results,
                message=message,
                handoff_to="AuditAgent",
            )
            context.trace["mitigation"] = results
            return results

        memory = get_memory_snapshot(context.analysis.get("ip", "unknown"))
        if context.decision.get("decision") == "EXECUTE" and context.classification.get("type") != "None":
            mitigation_result = mitigate(
                {"type": context.classification["threat_type"], "threat_type": context.classification["threat_type"]},
                {
                    "ip": context.analysis.get("ip", "unknown"),
                    "applied_actions": memory["applied_actions"],
                    "confidence": context.classification["confidence"],
                    "escalated": context.trace["risk"]["escalation"]["status"],
                },
            )
            updated_memory = register_applied_actions(context.analysis.get("ip", "unknown"), mitigation_result.get("action_keys", []), time.time())
            context.artifacts["memory"] = {
                "events_last_60s": len(updated_memory["events"]),
                "applied_actions": sorted(updated_memory["applied_actions"]),
            }
            context.trace.setdefault("risk", {})
            context.trace["risk"]["memory"] = {
                "events_last_60s": len(updated_memory["events"]),
                "applied_actions_count": len(updated_memory["applied_actions"]),
            }

            for action in mitigation_result["actions"]:
                action_record_id = create_action(
                    context.incident_id,
                    context.request_id,
                    action["action"],
                    action["impact"],
                    "COMPLETED",
                    mitigation_result.get("enforcement_scope", "control_plane_demo"),
                    {
                        "threat_type": context.classification["threat_type"],
                        "target_ip": context.analysis.get("ip"),
                    },
                )
                stored_action = dict(action)
                stored_action["action_record_id"] = action_record_id
                context.actions.append(stored_action)
                results["actions"].append(stored_action)

            follow_up_task = task_manager_tool.create_task(
                title=f"Validate mitigation for {context.classification['threat_type']}",
                description=f"Confirm mitigation outcome for incident {context.incident_id} and target {context.analysis.get('ip', 'unknown')}.",
                incident_id=context.incident_id,
                priority="HIGH",
                source_agent=self.name,
            )
            context.tasks.append(follow_up_task)
            results["tasks"].append(follow_up_task)
            message = f"Applied {len(results['actions'])} mitigation actions and created follow-up task."
        elif context.decision.get("decision") == "OBSERVE":
            follow_up_task = task_manager_tool.create_task(
                title=f"Investigate incident {context.incident_id}",
                description=f"Review observed threat {context.classification['threat_type']} from {context.analysis.get('ip', 'unknown')}.",
                incident_id=context.incident_id,
                priority="MEDIUM",
                source_agent=self.name,
            )
            context.tasks.append(follow_up_task)
            results["tasks"].append(follow_up_task)
            message = "Created analyst investigation task for observed incident."
        else:
            message = "No mitigation action required for this request."

        context.trace["mitigation"] = results
        self._record(
            context,
            step_name="act",
            status="COMPLETED",
            input_payload={"decision": context.decision, "classification": context.classification},
            output_payload=results,
            message=message,
            handoff_to="AuditAgent",
        )
        return results


class AuditAgent(BaseRoleAgent):
    name = "AuditAgent"

    async def run(self, context: ExecutionContext) -> dict:
        incident_summary = build_summary(context)
        incident_status = "ACTIONED" if context.decision.get("decision") == "EXECUTE" else "OPEN"
        existing_incident = get_incident(context.incident_id) or {}
        existing_metadata = existing_incident.get("metadata_json") or {}
        metadata_payload = {
            **existing_metadata,
            "request_type": context.request_type,
            "confidence_bucket": context.classification.get("confidence_bucket"),
            "adk_review": context.decision.get("adk_review", {}),
            "trace_snapshot": context.trace,
        }

        update_kwargs = {
            "status": incident_status,
            "summary": incident_summary,
            "threat_type": context.classification.get("threat_type"),
            "decision": context.decision.get("decision"),
            "source_ip": context.analysis.get("ip"),
            "metadata": metadata_payload,
        }

        if context.request_type == "task_command" and existing_incident:
            update_kwargs["status"] = existing_incident.get("status") or incident_status
            update_kwargs["summary"] = existing_incident.get("summary") or incident_summary
            update_kwargs["threat_type"] = existing_incident.get("threat_type") or context.classification.get("threat_type")
            update_kwargs["decision"] = existing_incident.get("decision") or context.decision.get("decision")
            update_kwargs["source_ip"] = existing_incident.get("source_ip") or context.analysis.get("ip")

        update_incident(
            context.incident_id,
            **update_kwargs,
        )

        workspace = {
            "incident": get_incident(context.incident_id),
            "tasks": list_tasks(incident_id=context.incident_id),
            "actions": list_actions(incident_id=context.incident_id),
            "agent_runs": list_agent_runs(incident_id=context.incident_id),
            "recent_incidents": list_recent_incidents(limit=5),
        }
        context.artifacts["workspace"] = workspace
        context.trace["audit"] = workspace

        self._record(
            context,
            step_name="record",
            status="COMPLETED",
            input_payload={"incident_id": context.incident_id},
            output_payload={"workspace": workspace, "summary": incident_summary},
            message="Persisted incident workspace, tasks, actions, and agent runs.",
            handoff_to=None,
        )
        return workspace


def build_summary(context: ExecutionContext) -> str:
    target_ip = context.analysis.get("ip") or "unknown"
    if context.request_type == "task_command":
        command = context.metadata.get("task_command", {})
        return f"Task command {command.get('action', 'list')} executed for incident {context.incident_id}."

    summary = f"{context.classification.get('threat_type', 'Unknown')} detected (Risk: {context.classification.get('risk_score', 0.0)})"
    summary += f" -> Decision: {context.decision.get('decision', 'IGNORE')}"
    if context.decision.get("decision") == "EXECUTE":
        summary += f" -> Mitigation applied to {target_ip}."
    elif context.decision.get("decision") == "OBSERVE":
        summary += f" -> Analyst task created for {target_ip}."
    else:
        summary += " -> Logged for reference."
    return summary


def build_agent_summary(context: ExecutionContext) -> list[str]:
    summary = []
    executed_agents = {
        step.get("agent")
        for step in context.trace.get("agent_orchestration", {}).get("executed_steps", [])
        if step.get("agent")
    }
    threat_type = context.classification.get("threat_type", "Unknown")
    confidence_bucket = context.classification.get("confidence_bucket", "LOW")
    detection_mode = context.classification.get("detection_mode", "fallback")
    deterministic_match = context.classification.get("deterministic_match", False)
    risk_trace = context.trace.get("risk", {})
    escalation = risk_trace.get("escalation", {})
    adk_review = context.decision.get("adk_review", {})
    actions_count = len(context.actions)
    tasks_count = len(context.tasks)

    if "DetectionAgent" in executed_agents:
        summary.append(
            f"DetectionAgent identified {threat_type} using {detection_mode}"
            + (" with deterministic proof." if deterministic_match else ".")
        )

    if "RiskAgent" in executed_agents:
        if adk_review.get("influenced_outcome"):
            summary.append(
                f"RiskAgent delegated the {confidence_bucket.lower()}-confidence case to ADK and selected {context.decision.get('decision', 'IGNORE')}."
            )
        elif escalation.get("status"):
            summary.append(
                f"RiskAgent escalated due to {escalation.get('profile', 'burst')} activity and selected {context.decision.get('decision', 'IGNORE')}."
            )
        else:
            summary.append(
                f"RiskAgent kept deterministic authority and selected {context.decision.get('decision', 'IGNORE')}."
            )

    if "MitigationAgent" in executed_agents:
        if actions_count:
            summary.append(f"MitigationAgent applied {actions_count} control-plane action(s).")
        elif tasks_count:
            summary.append(f"MitigationAgent created {tasks_count} follow-up task(s).")
        else:
            summary.append("MitigationAgent determined no immediate response action was required.")

    if "AuditAgent" in executed_agents:
        if context.trace.get("agent_orchestration", {}).get("failures"):
            summary.append("AuditAgent recorded a degraded workflow and preserved failure details for review.")
        else:
            summary.append("AuditAgent persisted the incident workspace, task state, and agent collaboration trail.")

    return summary


def restore_incident_snapshot(incident: dict) -> tuple[dict, dict]:
    metadata = incident.get("metadata_json") or {}
    trace_snapshot = metadata.get("trace_snapshot") or {}
    detection_snapshot = trace_snapshot.get("detection") or {}
    analysis = detection_snapshot.get("analysis") or {}
    classification = detection_snapshot.get("classification") or {}
    return dict(analysis), json.loads(json.dumps(classification)) if classification else {}


class CoordinatorAgent(BaseRoleAgent):
    name = "CoordinatorAgent"

    def __init__(self) -> None:
        self.detection_agent = DetectionAgent()
        self.risk_agent = RiskAgent()
        self.mitigation_agent = MitigationAgent()
        self.audit_agent = AuditAgent()

    def plan(self, context: ExecutionContext) -> list[dict]:
        planned = plan_workflow_tool(context.request_type, request_summary=context.raw_input)
        return planned["steps"]

    def route(self, step: dict):
        agent_name = step["agent"]
        if agent_name == "DetectionAgent":
            return self.detection_agent
        if agent_name == "RiskAgent":
            return self.risk_agent
        if agent_name == "MitigationAgent":
            return self.mitigation_agent
        if agent_name == "AuditAgent":
            return self.audit_agent
        return self

    async def handle(self, request_type: str, payload: dict, user_id: str = "demo", session_id: str | None = None) -> dict:
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        raw_input, source, metadata = self._extract_request_details(request_type, payload)
        incident_id = payload.get("incident_id") or create_incident(
            request_id=request_id,
            request_type=request_type,
            user_id=user_id,
            session_id=session_id,
            metadata={"source": source},
        )
        context = ExecutionContext(
            request_id=request_id,
            incident_id=incident_id,
            request_type=request_type,
            raw_input=raw_input,
            normalized_input=raw_input.lower().strip(),
            user_id=user_id,
            session_id=session_id,
            source=source,
            metadata=metadata,
        )
        context.plan = self.plan(context)
        self._record(
            context,
            step_name="plan",
            status="COMPLETED",
            input_payload={"request_type": request_type, "payload": payload},
            output_payload={"plan": context.plan},
            message=f"Planned {len(context.plan)} agent steps for {request_type}.",
            handoff_to=context.plan[1]["agent"] if len(context.plan) > 1 else None,
        )
        orchestration_trace = context.trace.setdefault(
            "agent_orchestration",
            {
                "execution_mode": "plan_driven_workflow",
                "executed_steps": [],
                "failures": [],
            },
        )
        deferred_audit_step = None

        for step in context.plan:
            agent_name = step["agent"]
            if agent_name == "CoordinatorAgent":
                continue
            if agent_name == "AuditAgent":
                deferred_audit_step = step
                continue

            if agent_name == "DetectionAgent":
                agent = self.detection_agent
            elif agent_name == "RiskAgent":
                agent = self.risk_agent
            elif agent_name == "MitigationAgent":
                agent = self.mitigation_agent
            else:
                continue
            execution_entry = {
                "agent": agent_name,
                "step": step.get("step", "run"),
                "status": "STARTED",
                "timestamp": time.time(),
            }
            orchestration_trace["executed_steps"].append(execution_entry)
            try:
                await agent.run(context)
                execution_entry["status"] = "COMPLETED"
            except Exception as exc:
                error_text = f"{type(exc).__name__}: {exc}"
                execution_entry["status"] = "FAILED"
                execution_entry["error"] = error_text
                orchestration_trace["failures"].append(
                    {
                        "agent": agent_name,
                        "step": step.get("step", "run"),
                        "status": "FAILED",
                        "error": error_text,
                        "timestamp": time.time(),
                    }
                )
                agent._record(
                    context,
                    step_name=step.get("step", "run"),
                    status="FAILED",
                    input_payload={"step": step, "request_type": request_type},
                    output_payload={"error": error_text},
                    message=f"{agent_name} failed during {step.get('step', 'run')}: {error_text}",
                    handoff_to="AuditAgent",
                )
                context.agent_messages[-1]["error"] = error_text
                break

        if deferred_audit_step:
            audit_entry = {
                "agent": "AuditAgent",
                "step": deferred_audit_step.get("step", "record"),
                "status": "STARTED",
                "timestamp": time.time(),
            }
            orchestration_trace["executed_steps"].append(audit_entry)
            try:
                await self.audit_agent.run(context)
                audit_entry["status"] = "COMPLETED"
            except Exception as exc:
                error_text = f"{type(exc).__name__}: {exc}"
                audit_entry["status"] = "FAILED"
                audit_entry["error"] = error_text
                orchestration_trace["failures"].append(
                    {
                        "agent": "AuditAgent",
                        "step": deferred_audit_step.get("step", "record"),
                        "status": "FAILED",
                        "error": error_text,
                        "timestamp": time.time(),
                    }
                )
                self.audit_agent._record(
                    context,
                    step_name=deferred_audit_step.get("step", "record"),
                    status="FAILED",
                    input_payload={"incident_id": context.incident_id},
                    output_payload={"error": error_text},
                    message=f"AuditAgent failed during {deferred_audit_step.get('step', 'record')}: {error_text}",
                    handoff_to=None,
                )

        return self.aggregate(context)

    def aggregate(self, context: ExecutionContext) -> dict:
        summary = build_summary(context)
        workspace = context.artifacts.get("workspace", {})
        agent_summary = build_agent_summary(context)
        context.metadata["agent_summary"] = agent_summary
        failures = context.trace.get("agent_orchestration", {}).get("failures", [])
        workflow_status = "DEGRADED" if failures else "COMPLETED"
        return {
            "system_name": SYSTEM_NAME,
            "request_id": context.request_id,
            "incident_id": context.incident_id,
            "request_type": context.request_type,
            "summary": summary,
            "agent_summary": agent_summary,
            "workflow_status": workflow_status,
            "plan": context.plan,
            "agent_results": context.agent_results,
            "agent_messages": context.agent_messages,
            "tasks": workspace.get("tasks", context.tasks),
            "actions": workspace.get("actions", context.actions),
            "trace": {
                "authoritative_source": "deterministic_agents_with_adk_low_confidence_review",
                "stage_1_input": {
                    "status": "COMPLETED",
                    "raw": context.raw_input,
                    "normalized": context.normalized_input,
                    "request_type": context.request_type,
                },
                "stage_2_log_analysis": context.analysis,
                "stage_3_threat_detection": context.classification,
                "stage_4_decision": context.decision,
                "stage_4b_escalation": context.trace.get("risk", {}).get("escalation", {}),
                "stage_5_mitigation": {
                    "actions": context.actions,
                    "tasks": context.tasks,
                },
                "stage_6_memory_state": context.trace.get("risk", {}).get("memory", {}),
                "agent_orchestration": {
                    "plan": context.plan,
                    "execution_mode": context.trace.get("agent_orchestration", {}).get("execution_mode", "plan_driven_workflow"),
                    "executed_steps": context.trace.get("agent_orchestration", {}).get("executed_steps", []),
                    "failures": failures,
                    "workflow_status": workflow_status,
                    "agent_summary": agent_summary,
                    "agent_messages": context.agent_messages,
                    "agent_runs": workspace.get("agent_runs", []),
                },
                "incident_workspace": workspace,
            },
            "workspace": workspace,
        }

    def _extract_request_details(self, request_type: str, payload: dict) -> tuple[str, str, dict]:
        if request_type == "task_command":
            action = payload.get("action", "list")
            raw_input = payload.get("description") or payload.get("title") or f"task_command:{action}"
            return raw_input, "task_manager", {"task_command": payload}
        if request_type == "incident_followup":
            raw_input = payload.get("message") or payload.get("raw") or "incident_followup"
            return raw_input, payload.get("source", "analyst_console"), {"followup": payload}
        raw_input = payload.get("raw") or " ".join(
            part
            for part in [
                f"ip={payload.get('ip')}" if payload.get("ip") else "",
                f"method={payload.get('method')}" if payload.get("method") else "",
                f"path={payload.get('path')}" if payload.get("path") else "",
                f"payload={payload.get('payload')}" if payload.get("payload") else "",
            ]
            if part
        )
        return raw_input.strip(), payload.get("source", "assistant_api"), {"request_payload": payload}


coordinator_agent = CoordinatorAgent()
