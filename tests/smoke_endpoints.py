import asyncio
import json
import sys
from typing import Any
from pathlib import Path

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.main import app


API_KEY = "demo"


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def auth_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = {"x-api-key": API_KEY}
    if extra:
        headers.update(extra)
    return headers


async def read_json(response: httpx.Response) -> Any:
    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type:
        return response.json()
    return response.text


async def test_public_endpoints(client: httpx.AsyncClient) -> dict[str, Any]:
    results = {}

    response = await client.get("/health")
    body = await read_json(response)
    assert_true(response.status_code == 200, "/health should return 200")
    assert_true(body["status"] == "ok", "/health should return ok")
    results["/health"] = "ok"

    response = await client.get("/warmup")
    body = await read_json(response)
    assert_true(response.status_code == 200, "/warmup should return 200")
    assert_true(body["status"] == "ready", "/warmup should return ready")
    results["/warmup"] = "ok"

    response = await client.get("/metrics-json")
    body = await read_json(response)
    assert_true(response.status_code == 200, "/metrics-json should return 200")
    assert_true("system_name" in body, "/metrics-json should include system_name")
    results["/metrics-json"] = "ok"

    response = await client.get("/")
    body = await read_json(response)
    assert_true(response.status_code == 200, "/ should return 200")
    assert_true("Multi-Agent Security Operations Assistant" in body, "/ should return dashboard HTML")
    results["/"] = "ok"

    response = await client.get("/latest")
    assert_true(response.status_code == 200, "/latest should return 200")
    results["/latest_initial"] = "ok"

    return results


async def test_task_endpoints(client: httpx.AsyncClient) -> tuple[dict[str, Any], str]:
    results = {}

    response = await client.get("/tasks")
    assert_true(response.status_code == 401, "Unauthorized /tasks should return 401")
    results["/tasks_unauthorized"] = "ok"

    response = await client.post(
        "/tasks",
        headers=auth_headers({"Content-Type": "application/json"}),
        content=json.dumps(
            {
                "title": "Smoke test task",
                "description": "Created during endpoint smoke test",
                "priority": "MEDIUM",
                "owner": "analyst",
            }
        ),
    )
    body = await read_json(response)
    assert_true(response.status_code == 200, "Authorized /tasks create should return 200")
    assert_true(bool(body.get("id")), "Created task should include id")
    task_id = body["id"]
    results["/tasks_create"] = "ok"

    response = await client.get("/tasks", headers=auth_headers())
    body = await read_json(response)
    assert_true(response.status_code == 200, "Authorized /tasks list should return 200")
    assert_true(isinstance(body.get("tasks"), list), "/tasks list should return tasks array")
    assert_true(any(task.get("id") == task_id for task in body["tasks"]), "Created task should appear in /tasks list")
    results["/tasks_list"] = "ok"

    response = await client.post(f"/tasks/{task_id}/complete", headers=auth_headers())
    body = await read_json(response)
    assert_true(response.status_code == 200, "/tasks/{task_id}/complete should return 200")
    assert_true(body.get("status") == "COMPLETED", "Completed task should return COMPLETED status")
    results["/tasks_complete"] = "ok"

    return results, task_id


async def test_assistant_endpoints(client: httpx.AsyncClient) -> tuple[dict[str, Any], str]:
    results = {}

    response = await client.post(
        "/assistant/request",
        headers=auth_headers({"Content-Type": "application/json"}),
        content=json.dumps(
            {
                "request_type": "log_triage",
                "payload": {
                    "raw": "ip=192.168.1.5 method=POST path=/login payload=admin' OR/**/1=1"
                },
                "user_id": "demo",
            }
        ),
    )
    body = await read_json(response)
    assert_true(response.status_code == 200, "/assistant/request log_triage should return 200")
    assert_true(body.get("incident_id"), "Assistant response should include incident_id")
    assert_true(body.get("workflow_status") in {"COMPLETED", "DEGRADED"}, "Assistant response should include workflow_status")
    assert_true(isinstance(body.get("agent_summary"), list), "Assistant response should include agent_summary")
    assert_true(
        body.get("trace", {}).get("stage_6_memory_state", {}).get("applied_actions_count", 0) >= 1,
        "Post-mitigation memory state should record applied actions",
    )
    incident_id = body["incident_id"]
    results["/assistant_request_log_triage"] = "ok"

    response = await client.post(
        "/assistant/request",
        headers=auth_headers({"Content-Type": "application/json"}),
        content=json.dumps(
            {
                "request_type": "incident_followup",
                "payload": {
                    "incident_id": incident_id,
                    "message": "Please investigate next steps for this incident.",
                    "source": "analyst_console",
                },
                "user_id": "demo",
            }
        ),
    )
    body = await read_json(response)
    assert_true(response.status_code == 200, "/assistant/request incident_followup should return 200")
    assert_true(body.get("request_type") == "incident_followup", "Follow-up response should preserve request_type")
    assert_true(
        body.get("trace", {}).get("stage_3_threat_detection", {}).get("threat_type") == "SQL Injection",
        "Incident follow-up should reuse the original incident classification",
    )
    assert_true(
        body.get("trace", {}).get("stage_3_threat_detection", {}).get("detection_mode") == "deterministic",
        "Incident follow-up should preserve deterministic classification when available",
    )
    results["/assistant_request_incident_followup"] = "ok"

    response = await client.post(
        "/assistant/request",
        headers=auth_headers({"Content-Type": "application/json"}),
        content=json.dumps(
            {
                "request_type": "task_command",
                "payload": {
                    "action": "create",
                    "title": "Analyst follow-up",
                    "description": "Review smoke-test incident",
                    "incident_id": incident_id,
                    "priority": "HIGH",
                },
                "user_id": "demo",
            }
        ),
    )
    body = await read_json(response)
    assert_true(response.status_code == 200, "/assistant/request task_command should return 200")
    assert_true(body.get("request_type") == "task_command", "Task command response should preserve request_type")
    assert_true(
        "Task command" not in (body.get("workspace", {}).get("incident", {}) or {}).get("summary", ""),
        "Task commands should not overwrite the primary incident summary",
    )
    results["/assistant_request_task_command"] = "ok"

    response = await client.post(
        "/agent-test",
        headers=auth_headers({"Content-Type": "application/json"}),
        content=json.dumps(
            {
                "prompt": "Review this low-confidence security event: ip=10.0.0.9 method=GET path=/home payload=totally_benign_but_unclear"
            }
        ),
    )
    body = await read_json(response)
    assert_true(response.status_code == 200, "/agent-test should return 200")
    assert_true(isinstance(body, dict), "/agent-test should return JSON object")
    results["/agent-test"] = body.get("adk_status", "ok")

    response = await client.post(
        "/ingest-log",
        headers=auth_headers({"Content-Type": "application/json", "x-event-id": "smoke-eid-1"}),
        content=json.dumps(
            {
                "ip": "192.168.1.6",
                "method": "GET",
                "path": "/download",
                "payload": "../../etc/passwd",
                "source": "assistant_api",
            }
        ),
    )
    body = await read_json(response)
    assert_true(response.status_code == 200, "/ingest-log should return 200")
    assert_true(body.get("request_type") == "log_triage", "/ingest-log should return log_triage compatibility response")
    results["/ingest-log"] = "ok"

    response = await client.get("/latest")
    body = await read_json(response)
    assert_true(response.status_code == 200, "/latest after activity should return 200")
    assert_true(bool(body.get("summary")), "/latest should return populated summary after requests")
    results["/latest_after_activity"] = "ok"

    escalation_body = None
    for index in range(4):
        response = await client.post(
            "/assistant/request",
            headers=auth_headers({"Content-Type": "application/json"}),
            content=json.dumps(
                {
                    "request_type": "log_triage",
                    "payload": {
                        "raw": "ip=172.16.0.50 method=POST path=/login payload=login failed"
                    },
                    "user_id": "demo",
                }
            ),
        )
        escalation_body = await read_json(response)
        assert_true(response.status_code == 200, f"Burst escalation request {index + 1} should return 200")

    escalation_trace = escalation_body.get("trace", {}).get("stage_4_decision", {})
    assert_true("Aggressive Attacker" in json.dumps(escalation_body), "Burst escalation should mark aggressive attacker behavior")
    assert_true("escalation_active = True" in escalation_trace.get("decision_trace", []), "Burst escalation should show active escalation in decision trace")
    assert_true(escalation_body.get("trace", {}).get("stage_4_decision", {}).get("decision") == "EXECUTE", "Burst escalation should lead to EXECUTE")
    assert_true(escalation_body.get("trace", {}).get("stage_6_memory_state", {}).get("events_last_60s", 0) >= 3, "Burst escalation should show multiple recent events")
    results["/assistant_request_burst_escalation"] = "ok"

    return results, incident_id


async def main() -> None:
    results: dict[str, Any] = {}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        results.update(await test_public_endpoints(client))
        task_results, _ = await test_task_endpoints(client)
        results.update(task_results)
        assistant_results, incident_id = await test_assistant_endpoints(client)
        results.update(assistant_results)
        results["last_incident_id"] = incident_id

    print(json.dumps({"status": "ok", "results": results}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
