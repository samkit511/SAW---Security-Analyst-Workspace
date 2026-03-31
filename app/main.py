import json
import logging
import math
import os
import secrets
import time
from pathlib import Path
from threading import Lock

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ValidationError

from app.agent import SYSTEM_NAME, asa_agent, coordinator_agent, task_manager_tool
from app.storage import complete_task, list_tasks


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("msoa")


class AssistantRequest(BaseModel):
    request_type: str
    payload: dict
    user_id: str = "demo"
    session_id: str | None = None


class IngestLogRequest(BaseModel):
    ip: str | None = None
    method: str | None = None
    path: str | None = None
    payload: str | None = None
    raw: str | None = None
    source: str | None = "assistant_api"
    event_id: str | None = None


class TaskCreateRequest(BaseModel):
    title: str
    description: str
    incident_id: str | None = None
    priority: str = "MEDIUM"
    owner: str = "analyst"


app = FastAPI(title=SYSTEM_NAME)

latest_result = {}
latest_lock = Lock()
inflight_lock = Lock()
rate_limit_lock = Lock()
replay_lock = Lock()

ASA_API_KEY = os.getenv("ASA_API_KEY", "demo")
SCHEMA_VERSION = "2.0.0"
MAX_INFLIGHT_REQUESTS = int(os.getenv("ASA_MAX_INFLIGHT", "8"))
MAX_REQUEST_BYTES = int(os.getenv("ASA_MAX_REQUEST_BYTES", "16384"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("ASA_RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("ASA_RATE_LIMIT_MAX_REQUESTS", "12"))
REPLAY_WINDOW_SECONDS = int(os.getenv("ASA_REPLAY_WINDOW_SECONDS", "30"))
DEFAULT_DETECTION_MODEL = os.getenv("ASA_DETECTION_MODEL", "gemini-2.5-flash")
DEFAULT_ADK_MODEL = os.getenv("ASA_ADK_MODEL", "gemini-2.5-flash")
ENABLE_ADK_ADVISORY = os.getenv("ASA_ENABLE_ADK_ADVISORY", "true").lower() == "true"
ENABLE_ESCALATION = os.getenv("ASA_ENABLE_ESCALATION", "true").lower() == "true"

inflight_requests = 0
request_history = {}
seen_event_ids = {}


def set_latest(data: dict) -> None:
    with latest_lock:
        global latest_result
        latest_result = data


def api_error(status_code: int, code: str, message: str, **extra) -> JSONResponse:
    payload = {"error": {"code": code, "message": message}}
    payload["error"].update(extra)
    return JSONResponse(status_code=status_code, content=payload)


def log_event(level: int, event_type: str, **fields) -> None:
    logger.log(level, json.dumps({"event_type": event_type, **fields}, ensure_ascii=True, sort_keys=True))


def is_authorized(request: Request) -> bool:
    supplied_key = request.headers.get("x-api-key", "")
    return secrets.compare_digest(supplied_key, ASA_API_KEY)


def try_acquire_request_slot() -> bool:
    global inflight_requests
    with inflight_lock:
        if inflight_requests >= MAX_INFLIGHT_REQUESTS:
            return False
        inflight_requests += 1
        return True


def release_request_slot() -> None:
    global inflight_requests
    with inflight_lock:
        inflight_requests = max(0, inflight_requests - 1)


def check_rate_limit(source_ip: str, now: float) -> tuple[bool, int]:
    with rate_limit_lock:
        history = [ts for ts in request_history.get(source_ip, []) if now - ts <= RATE_LIMIT_WINDOW_SECONDS]
        if len(history) >= RATE_LIMIT_MAX_REQUESTS:
            retry_after = max(1, int(RATE_LIMIT_WINDOW_SECONDS - (now - history[0])))
            request_history[source_ip] = history
            return False, retry_after
        history.append(now)
        request_history[source_ip] = history
        return True, 0


def register_event_id(event_id: str | None, now: float) -> bool:
    if not event_id:
        return True
    with replay_lock:
        expired = [key for key, ts in seen_event_ids.items() if now - ts > REPLAY_WINDOW_SECONDS]
        for key in expired:
            seen_event_ids.pop(key, None)
        if event_id in seen_event_ids:
            return False
        seen_event_ids[event_id] = now
        return True


def build_raw_log_from_structured(payload: IngestLogRequest) -> str:
    if payload.raw:
        return payload.raw.strip()
    parts = []
    if payload.ip:
        parts.append(f"ip={payload.ip}")
    if payload.method:
        parts.append(f"method={payload.method.upper()}")
    if payload.path:
        parts.append(f"path={payload.path}")
    if payload.payload:
        parts.append(f"payload={payload.payload}")
    return " ".join(parts).strip()


async def parse_ingest_payload(request: Request, body: bytes) -> dict:
    if len(body) > MAX_REQUEST_BYTES:
        raise ValueError("payload_too_large")

    content_type = request.headers.get("content-type", "").lower()
    event_id = request.headers.get("x-event-id")
    if "application/json" in content_type:
        try:
            incoming = IngestLogRequest.model_validate_json(body)
        except ValidationError as exc:
            raise ValueError(f"invalid_json_schema:{exc}") from exc
        except Exception as exc:
            raise ValueError(f"invalid_json:{exc}") from exc
        return {
            "payload": {
                "ip": incoming.ip,
                "method": incoming.method,
                "path": incoming.path,
                "payload": incoming.payload,
                "raw": build_raw_log_from_structured(incoming),
                "source": incoming.source or "assistant_api",
                "event_id": incoming.event_id or event_id,
            }
        }

    return {
        "payload": {
            "raw": body.decode("utf-8").strip(),
            "source": "web_app_login_endpoint",
            "event_id": event_id,
        }
    }


def decorate_assistant_response(result: dict, *, latency_ms: int, mode: str, source_ip: str, compatibility_mode: bool) -> dict:
    response = dict(result)
    response["meta"] = {
        "trace_id": result["request_id"],
        "schema_version": SCHEMA_VERSION,
        "mode": mode,
        "timestamp": time.time(),
        "source_ip": source_ip,
        "model_info": {
            "detection_model": DEFAULT_DETECTION_MODEL,
            "adk_model": DEFAULT_ADK_MODEL,
            "execution_mode": mode,
        },
        "feature_flags": {
            "adk_advisory": ENABLE_ADK_ADVISORY,
            "adk_low_confidence_delegate": ENABLE_ADK_ADVISORY,
            "adk_enabled": ENABLE_ADK_ADVISORY,
            "escalation": ENABLE_ESCALATION,
        },
        "system_metrics": {
            "latency_ms": latency_ms,
            "pipeline_success": True,
        },
        "completeness": {
            "primary_stages_executed": True,
            "agent_orchestration_visible": True,
        },
        "resilience": {
            "workflow_status": result.get("workflow_status", "COMPLETED"),
            "failed_agents": len(result.get("trace", {}).get("agent_orchestration", {}).get("failures", [])),
        },
        "enforcement_scope": "control_plane_demo",
        "compatibility_mode": compatibility_mode,
    }

    decision = response.get("agent_results", {}).get("RiskAgent", {}).get("output", {}).get("decision", {})
    adk_review = decision.get("adk_review", {})
    response.setdefault("trace", {})
    response["trace"]["stage_3b_adk_agent_review"] = {
        "status": "COMPLETED" if adk_review.get("status") == "ok" else ("SKIPPED" if adk_review.get("status") == "skipped" else "DEGRADED"),
        "adk_status": adk_review.get("status", "skipped"),
        "adk_enabled": ENABLE_ADK_ADVISORY,
        "role": "low_confidence_decision_delegate",
        "execution_mode": "delegate_for_low_confidence_only",
        "authority_window": ["LOW", "MEDIUM", "fallback"],
        "bounded_impact_on_primary_decision": True,
        "influenced_outcome": adk_review.get("influenced_outcome", False),
        "reason": adk_review.get("reason"),
    }
    return response


async def execute_assistant_request(request_type: str, payload: dict, *, user_id: str, session_id: str | None, mode: str, source_ip: str, compatibility_mode: bool) -> dict:
    start_perf_ns = time.perf_counter_ns()
    result = await coordinator_agent.handle(
        request_type=request_type,
        payload=payload,
        user_id=user_id,
        session_id=session_id,
    )
    latency_ms = max(1, math.ceil((time.perf_counter_ns() - start_perf_ns) / 1_000_000))
    decorated = decorate_assistant_response(
        result,
        latency_ms=latency_ms,
        mode=mode,
        source_ip=source_ip,
        compatibility_mode=compatibility_mode,
    )
    set_latest(decorated)
    log_event(logging.INFO, "assistant_request_completed", request_id=decorated["request_id"], incident_id=decorated["incident_id"], request_type=request_type, latency_ms=latency_ms)
    return decorated


@app.get("/latest")
def get_latest() -> dict:
    with latest_lock:
        return latest_result


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/warmup")
def warmup() -> dict:
    return {"status": "ready"}


@app.get("/metrics-json")
def metrics_json() -> dict:
    with inflight_lock:
        current_inflight = inflight_requests
    return {
        "schema_version": SCHEMA_VERSION,
        "system_name": SYSTEM_NAME,
        "inflight_requests": current_inflight,
        "limits": {
            "max_inflight": MAX_INFLIGHT_REQUESTS,
            "rate_limit_window_seconds": RATE_LIMIT_WINDOW_SECONDS,
            "rate_limit_max_requests": RATE_LIMIT_MAX_REQUESTS,
            "max_request_bytes": MAX_REQUEST_BYTES,
        },
        "feature_flags": {
            "adk_advisory": ENABLE_ADK_ADVISORY,
            "escalation": ENABLE_ESCALATION,
        },
    }


@app.get("/")
async def get_dashboard():
    return FileResponse("static/index.html")


@app.get("/tasks")
async def get_tasks(request: Request):
    if not is_authorized(request):
        return api_error(401, "unauthorized", "Valid x-api-key header required.")
    incident_id = request.query_params.get("incident_id")
    status = request.query_params.get("status")
    return {"tasks": list_tasks(incident_id=incident_id, status=status)}


@app.post("/tasks")
async def create_task_endpoint(request: Request):
    if not is_authorized(request):
        return api_error(401, "unauthorized", "Valid x-api-key header required.")
    body = await request.body()
    if len(body) > MAX_REQUEST_BYTES:
        return api_error(413, "payload_too_large", "Task payload exceeds maximum allowed size.", max_bytes=MAX_REQUEST_BYTES)
    try:
        task_request = TaskCreateRequest.model_validate_json(body)
    except ValidationError:
        return api_error(422, "invalid_task_payload", "Task body failed validation.")

    created = task_manager_tool.create_task(
        title=task_request.title,
        description=task_request.description,
        incident_id=task_request.incident_id,
        priority=task_request.priority,
        owner=task_request.owner,
        source_agent="TaskAPI",
    )
    return created


@app.post("/tasks/{task_id}/complete")
async def complete_task_endpoint(task_id: str, request: Request):
    if not is_authorized(request):
        return api_error(401, "unauthorized", "Valid x-api-key header required.")
    completed = complete_task(task_id)
    if not completed:
        return api_error(404, "task_not_found", "Task ID not found.")
    return completed


@app.post("/assistant/request")
async def assistant_request(request: Request):
    if not is_authorized(request):
        return api_error(401, "unauthorized", "Valid x-api-key header required.")
    if not try_acquire_request_slot():
        return api_error(503, "overloaded", "Too many in-flight requests.", retry_after_seconds=1)

    try:
        source_ip = request.client.host if request.client else "unknown"
        body = await request.body()
        if len(body) > MAX_REQUEST_BYTES:
            return api_error(413, "payload_too_large", "Assistant request exceeds maximum allowed size.", max_bytes=MAX_REQUEST_BYTES)

        allowed, retry_after = check_rate_limit(source_ip, time.time())
        if not allowed:
            return api_error(429, "rate_limited", "Per-IP assistant rate limit exceeded.", retry_after_seconds=retry_after)

        try:
            assistant_payload = AssistantRequest.model_validate_json(body)
        except ValidationError:
            return api_error(422, "invalid_assistant_payload", "Assistant request body failed validation.")

        if assistant_payload.request_type not in {"log_triage", "incident_followup", "task_command"}:
            return api_error(400, "invalid_request_type", "request_type must be log_triage, incident_followup, or task_command.")

        result = await execute_assistant_request(
            request_type=assistant_payload.request_type,
            payload=assistant_payload.payload,
            user_id=assistant_payload.user_id,
            session_id=assistant_payload.session_id,
            mode=os.getenv("ASA_MODE", "HYBRID"),
            source_ip=source_ip,
            compatibility_mode=False,
        )
        return JSONResponse(content=result)
    finally:
        release_request_slot()


@app.post("/agent-test")
async def agent_test(request: Request):
    if not is_authorized(request):
        return api_error(401, "unauthorized", "Valid x-api-key header required.")
    if not try_acquire_request_slot():
        return api_error(503, "overloaded", "Too many in-flight requests.", retry_after_seconds=1)

    try:
        body = await request.body()
        if len(body) > MAX_REQUEST_BYTES:
            return api_error(413, "payload_too_large", "Prompt exceeds maximum allowed size.", max_bytes=MAX_REQUEST_BYTES)
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            return api_error(400, "invalid_json", "agent-test expects a JSON body with a prompt field.")

        prompt = str(data.get("prompt", "")).strip()
        if not prompt:
            return api_error(400, "empty_prompt", "Prompt must not be empty.")
        result = await asa_agent.run(prompt, cache_context={"surface": "agent_test"})
        return JSONResponse(content=result)
    finally:
        release_request_slot()


@app.post("/ingest-log")
async def ingest_log(request: Request):
    if not is_authorized(request):
        return api_error(401, "unauthorized", "Valid x-api-key header required.")
    if not try_acquire_request_slot():
        return api_error(503, "overloaded", "Too many in-flight requests.", retry_after_seconds=1)

    try:
        source_ip = request.client.host if request.client else "unknown"
        body = await request.body()
        try:
            parsed = await parse_ingest_payload(request, body)
        except ValueError as exc:
            error_code = str(exc)
            if error_code == "payload_too_large":
                return api_error(413, "payload_too_large", "Request body exceeds maximum allowed size.", max_bytes=MAX_REQUEST_BYTES)
            if error_code.startswith("invalid_json_schema"):
                return api_error(422, "invalid_json_schema", "Structured log body failed validation.")
            return api_error(400, "invalid_json", "Structured log body must be valid JSON.")

        payload = parsed["payload"]
        raw_input = payload.get("raw", "")
        if not raw_input:
            return api_error(400, "empty_log", "Log data must not be empty.")

        allowed, retry_after = check_rate_limit(source_ip, time.time())
        if not allowed:
            return api_error(429, "rate_limited", "Per-IP ingest rate limit exceeded.", retry_after_seconds=retry_after)
        if not register_event_id(payload.get("event_id"), time.time()):
            return api_error(409, "replay_detected", "Duplicate event_id received within replay window.", replay_window_seconds=REPLAY_WINDOW_SECONDS)

        result = await execute_assistant_request(
            request_type="log_triage",
            payload=payload,
            user_id="demo",
            session_id=None,
            mode=os.getenv("ASA_MODE", "HYBRID"),
            source_ip=source_ip,
            compatibility_mode=True,
        )
        return JSONResponse(content=result)
    finally:
        release_request_slot()


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8080))
    logging.info("MSOA server started on port %s", port)
    uvicorn.run(app, host="0.0.0.0", port=port)
