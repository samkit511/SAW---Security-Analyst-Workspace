# Multi-Agent Security Operations Assistant Walkthrough

This guide shows how to run the project locally, start the API server, and test every endpoint from your own machine.

## 1. Setup

Open PowerShell in the project folder:

```powershell
cd "C:\Users\samkit jain\Dropbox\PC\Desktop\Google_hackathon\project"
```

Create a virtual environment if needed:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Create your local env file:

```powershell
Copy-Item .sampleenv .env
```

If you want live Gemini / ADK responses, open `.env` and set either `GOOGLE_API_KEY` or `GEMINI_API_KEY`.

## 2. Start The Server

Run:

```powershell
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

Open the dashboard:

```text
http://127.0.0.1:8080
```

## 3. Run Full Automated Smoke Test

This runs an in-process endpoint sweep covering every FastAPI route:

```powershell
python .\tests\smoke_endpoints.py
```

Expected result:

```text
"status": "ok"
```

## 4. Manual Endpoint Tests

Set a reusable header variable:

```powershell
$headers = @{ "x-api-key" = "demo" }
```

### Public endpoints

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8080/health"
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8080/warmup"
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8080/metrics-json"
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8080/latest"
```

### Task endpoints

Create a task:

```powershell
$taskHeaders = @{ "x-api-key" = "demo"; "Content-Type" = "application/json" }
$taskBody = @{
  title = "Manual verification task"
  description = "Created from walkthrough"
  priority = "MEDIUM"
  owner = "analyst"
} | ConvertTo-Json

$task = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8080/tasks" -Headers $taskHeaders -Body $taskBody
$task
```

List tasks:

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:8080/tasks" -Headers $headers
```

Complete a task:

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8080/tasks/$($task.id)/complete" -Headers $headers
```

### Assistant request: log triage

```powershell
$assistantHeaders = @{ "x-api-key" = "demo"; "Content-Type" = "application/json" }
$logTriageBody = @{
  request_type = "log_triage"
  user_id = "demo"
  payload = @{
    raw = "ip=192.168.1.5 method=POST path=/login payload=admin' OR/**/1=1"
  }
} | ConvertTo-Json -Depth 6

$triage = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8080/assistant/request" -Headers $assistantHeaders -Body $logTriageBody
$triage
```

### Assistant request: incident follow-up

```powershell
$followupBody = @{
  request_type = "incident_followup"
  user_id = "demo"
  payload = @{
    incident_id = $triage.incident_id
    message = "Please review next steps for this incident."
    source = "analyst_console"
  }
} | ConvertTo-Json -Depth 6

Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8080/assistant/request" -Headers $assistantHeaders -Body $followupBody
```

### Assistant request: task command

```powershell
$taskCommandBody = @{
  request_type = "task_command"
  user_id = "demo"
  payload = @{
    action = "create"
    title = "Analyst follow-up"
    description = "Review incident from manual test"
    incident_id = $triage.incident_id
    priority = "HIGH"
  }
} | ConvertTo-Json -Depth 6

Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8080/assistant/request" -Headers $assistantHeaders -Body $taskCommandBody
```

### Agent test endpoint

```powershell
$agentBody = @{
  prompt = "Review this low-confidence security event: ip=10.0.0.9 method=GET path=/home payload=totally_benign_but_unclear"
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8080/agent-test" -Headers $assistantHeaders -Body $agentBody
```

### Ingest log endpoint

```powershell
$ingestHeaders = @{
  "x-api-key" = "demo"
  "Content-Type" = "application/json"
  "x-event-id" = "manual-event-1"
}

$ingestBody = @{
  ip = "192.168.1.6"
  method = "GET"
  path = "/download"
  payload = "../../etc/passwd"
  source = "assistant_api"
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8080/ingest-log" -Headers $ingestHeaders -Body $ingestBody
```

## 5. What To Look For

On successful tests, you should see:

- `workflow_status` as `COMPLETED` or `DEGRADED`
- `agent_summary` populated
- `trace.agent_orchestration.plan` populated
- `trace.stage_3b_adk_agent_review` present
- `incident_id` returned from assistant flows
- task creation and completion working

## 6. Common Issues

If the dashboard loads but ADK is not producing live model responses:

- verify `GOOGLE_API_KEY` or `GEMINI_API_KEY` is set in `.env`
- verify the API key has Gemini quota enabled
- rerun `pip install -r requirements.txt`

If PowerShell blocks venv activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## 7. Recommended Final Demo Flow

Run these in order:

1. `python .\tests\smoke_endpoints.py`
2. Start server with `uvicorn`
3. Open `http://127.0.0.1:8080`
4. Send one clean or low-signal request
5. Send one SQLi request
6. Send one path traversal request
7. Show `/latest` and the dashboard orchestration panel
