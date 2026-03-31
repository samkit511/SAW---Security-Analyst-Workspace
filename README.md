SAW (Security Analyst Workspace)
Multi-Agent Security Operations Assistant (MSOA)

## 📌 Project Overview (The 5W1H)

### **What** is it?
The Adaptive Security Agent (ASA) / Multi-Agent Security Operations Assistant (MSOA) is a production-grade multi-agent system designed for automated security log triage, threat classification, and incident mitigation tracking. It leverages a hybrid approach, combining fast pre-filtering with Deep AI reasoning capabilities.

### **Why** was it built?
To combat alert fatigue in Security Operations Centers (SOC). By automating repetitive log triaging tasks and applying deterministic and LLM-assisted validation, security analysts can focus their time on complex incidents that require human judgment, backed by consistent automated incident reporting.

### **Who** is it for?
Security Analysts, SOC Managers, and DevSecOps teams looking for an automated first-line defense investigator capable of providing consistent, explainable threat assessments.

### **When** should it be used?
It operates in real-time, ingesting logs and network behavior outputs from edge systems, firewalls, and application gateways as incidents occur, allowing for immediate automated triage.

### **Where** does it live?
It is deployed as a FastAPI backend service. It can run locally, in Docker containers, or directly integrated into Cloud infrastructure to act as a listener for security events.

### **How** does it work?
The system utilizes a multi-agent orchestration pattern (via Google ADK):
1. **Coordinator Agent**: Receives and plans the response workflow.
2. **Detection Agent**: Normalizes logs and classifies the initial threat type using heuristic rules or LLM checks.
3. **Risk Agent**: Scopes the severity of the alert, factors in historical attack memory (rapid escalation vs. single events), and formulates an action framework.
4. **Mitigation & Audit Agents**: Recommends immediate mitigations and records full explainable tracing.

---

## 🏗️ Architecture & Modes

The project operates primarily in a hybrid execution pattern:
*   **Deterministic Pipeline**: Applies standard signature-matching, rule-based filtering, and rate-limiting limits to drop or tag obvious issues quickly with near-zero latency.
*   **LLM-Assisted Pipeline**: For ambiguous or low-confidence logs, or when behavior overrides require complex thought, the system escalates to Google ADK-powered AI agents (Gemini) capable of examining contextual subtleties that bypass static rules.

---

## 🚀 Getting Started

Follow these steps to set up and run the ASA server on your local machine.

### Prerequisites
*   Python 3.10+
*   *(Optional but Recommended)* Google / Gemini API Key for active LLM agent reasoning.

### Installation

1.  **Open PowerShell** and navigate to your desired directory.
2.  **Clone / Prepare** your project folder.
3.  **Create a Virtual Environment**:
    ```powershell
    python -m venv .venv
    ```
4.  **Activate Native Environment**:
    ```powershell
    .\.venv\Scripts\Activate.ps1
    ```
5.  **Install the Dependencies**:
    ```powershell
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    ```
6.  **Environment Variables setup**:
    Copy the sample configuration file to instantiate your local `.env`.
    ```powershell
    Copy-Item .sampleenv .env
    ```
    Open `.env` in a text editor. Add your API Key to `GOOGLE_API_KEY=` or `GEMINI_API_KEY=` if you wish to run the LLM-assisted tools instead of pure deterministic fallback mode.

### Running the Server

Start the Uvicorn-based FastAPI real-time server:
```powershell
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

*The server will be reachable at `http://127.0.0.1:8080`.*
*(The root endpoint `/` serves an interactive frontend UI dash).*

---

## 🛠️ Tech Stack

*   **FastAPI / Uvicorn**: High-performance asynchronous API layer.
*   **Pydantic**: Robust schema enforcement and data validation.
*   **Google GenAI SDK**: Core interface for interaction with Gemini models.
*   **Google ADK**: Multi-agent orchestration, state sharing, and system boundaries.

---

## 📡 API Reference

Here are the critical REST endpoints for system integration:

### System & Health Endpoints
*   `GET /health`: Basic ping and uptime status.
*   `GET /metrics-json`: Live statistics for inflight requests, rate limits, and system status variables.
*   `GET /latest`: Fetches the response structure of the most recent processed incident for dashboarding.

### Analytics & Ingestion
*   `POST /ingest-log`: Primary endpoint. Accepts raw application strings or structured JSON to investigate a potential threat. Required Header: `x-api-key`.
*   `POST /assistant/request`: Flexible endpoint handles specific conversational request types like `"log_triage"`, `"incident_followup"`, or `"task_command"`.
*   `POST /agent-test`: Debugging route explicitly testing LLM orchestration against a prompt payload.

### Task Management
*   `GET /tasks`: Query the currently assigned tracking tasks / manual reviews remaining. Support incident filtering via `?incident_id=xyz`.
*   `POST /tasks`: Manually assign a follow up or review token for Analyst users.
*   `POST /tasks/{task_id}/complete`: Resolve an assigned investigation item.

---

*Built for robust SOC security triage and rapid threat deployment workflows. Stay secure!*
