import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path


DB_PATH = Path(os.getenv("ASA_DB_PATH", "data/assistant.db"))
DB_LOCK = threading.Lock()


def _ensure_parent() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    _ensure_parent()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    schema = """
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL,
        request_type TEXT NOT NULL,
        user_id TEXT NOT NULL,
        session_id TEXT,
        status TEXT NOT NULL,
        summary TEXT,
        threat_type TEXT,
        decision TEXT,
        source_ip TEXT,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        metadata_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        raw_input TEXT NOT NULL,
        normalized_input TEXT NOT NULL,
        source TEXT NOT NULL,
        source_ip TEXT,
        path TEXT,
        method TEXT,
        payload TEXT,
        created_at REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        action_name TEXT NOT NULL,
        impact TEXT NOT NULL,
        status TEXT NOT NULL,
        scope TEXT NOT NULL,
        details_json TEXT NOT NULL,
        created_at REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        incident_id TEXT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL,
        priority TEXT NOT NULL,
        owner TEXT NOT NULL,
        source_agent TEXT NOT NULL,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        completed_at REAL,
        metadata_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS agent_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        request_id TEXT NOT NULL,
        agent_name TEXT NOT NULL,
        step_name TEXT NOT NULL,
        status TEXT NOT NULL,
        input_json TEXT NOT NULL,
        output_json TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at REAL NOT NULL
    );
    """
    with DB_LOCK:
        conn = get_connection()
        try:
            conn.executescript(schema)
            conn.commit()
        finally:
            conn.close()


def _json(value) -> str:
    return json.dumps(value or {}, ensure_ascii=True, sort_keys=True)


def _row_to_dict(row):
    if row is None:
        return None
    data = dict(row)
    for key in ["metadata_json", "details_json", "input_json", "output_json"]:
        if key in data and data[key]:
            data[key] = json.loads(data[key])
    return data


def create_incident(request_id: str, request_type: str, user_id: str, session_id: str | None, metadata: dict | None = None) -> str:
    incident_id = f"inc_{uuid.uuid4().hex[:12]}"
    now = time.time()
    with DB_LOCK:
        conn = get_connection()
        try:
            conn.execute(
                """
                INSERT INTO incidents (
                    id, request_id, request_type, user_id, session_id, status, summary, threat_type,
                    decision, source_ip, created_at, updated_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    request_id,
                    request_type,
                    user_id,
                    session_id,
                    "OPEN",
                    "",
                    None,
                    None,
                    None,
                    now,
                    now,
                    _json(metadata),
                ),
            )
            conn.commit()
        finally:
            conn.close()
    return incident_id


def update_incident(
    incident_id: str,
    *,
    status: str | None = None,
    summary: str | None = None,
    threat_type: str | None = None,
    decision: str | None = None,
    source_ip: str | None = None,
    metadata: dict | None = None,
) -> None:
    updates = []
    values = []
    if status is not None:
        updates.append("status = ?")
        values.append(status)
    if summary is not None:
        updates.append("summary = ?")
        values.append(summary)
    if threat_type is not None:
        updates.append("threat_type = ?")
        values.append(threat_type)
    if decision is not None:
        updates.append("decision = ?")
        values.append(decision)
    if source_ip is not None:
        updates.append("source_ip = ?")
        values.append(source_ip)
    if metadata is not None:
        updates.append("metadata_json = ?")
        values.append(_json(metadata))
    updates.append("updated_at = ?")
    values.append(time.time())
    values.append(incident_id)

    with DB_LOCK:
        conn = get_connection()
        try:
            conn.execute(f"UPDATE incidents SET {', '.join(updates)} WHERE id = ?", values)
            conn.commit()
        finally:
            conn.close()


def get_incident(incident_id: str) -> dict | None:
    with DB_LOCK:
        conn = get_connection()
        try:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            return _row_to_dict(row)
        finally:
            conn.close()


def list_recent_incidents(limit: int = 10) -> list[dict]:
    with DB_LOCK:
        conn = get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [_row_to_dict(row) for row in rows]
        finally:
            conn.close()


def create_event(incident_id: str, request_id: str, raw_input: str, normalized_input: str, source: str, analysis: dict) -> int:
    now = time.time()
    with DB_LOCK:
        conn = get_connection()
        try:
            cursor = conn.execute(
                """
                INSERT INTO events (
                    incident_id, request_id, raw_input, normalized_input, source, source_ip, path,
                    method, payload, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    request_id,
                    raw_input,
                    normalized_input,
                    source,
                    analysis.get("ip"),
                    analysis.get("path"),
                    analysis.get("method"),
                    analysis.get("payload"),
                    now,
                ),
            )
            conn.commit()
            return int(cursor.lastrowid)
        finally:
            conn.close()


def create_action(incident_id: str, request_id: str, action_name: str, impact: str, status: str, scope: str, details: dict | None = None) -> int:
    now = time.time()
    with DB_LOCK:
        conn = get_connection()
        try:
            cursor = conn.execute(
                """
                INSERT INTO actions (
                    incident_id, request_id, action_name, impact, status, scope, details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    request_id,
                    action_name,
                    impact,
                    status,
                    scope,
                    _json(details),
                    now,
                ),
            )
            conn.commit()
            return int(cursor.lastrowid)
        finally:
            conn.close()


def list_actions(incident_id: str | None = None, limit: int = 20) -> list[dict]:
    query = "SELECT * FROM actions"
    params = []
    if incident_id:
        query += " WHERE incident_id = ?"
        params.append(incident_id)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with DB_LOCK:
        conn = get_connection()
        try:
            rows = conn.execute(query, tuple(params)).fetchall()
            return [_row_to_dict(row) for row in rows]
        finally:
            conn.close()


def create_task(
    title: str,
    description: str,
    *,
    incident_id: str | None = None,
    priority: str = "MEDIUM",
    owner: str = "analyst",
    source_agent: str = "CoordinatorAgent",
    metadata: dict | None = None,
) -> dict:
    task_id = f"task_{uuid.uuid4().hex[:12]}"
    now = time.time()
    with DB_LOCK:
        conn = get_connection()
        try:
            conn.execute(
                """
                INSERT INTO tasks (
                    id, incident_id, title, description, status, priority, owner, source_agent,
                    created_at, updated_at, completed_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    incident_id,
                    title,
                    description,
                    "OPEN",
                    priority,
                    owner,
                    source_agent,
                    now,
                    now,
                    None,
                    _json(metadata),
                ),
            )
            conn.commit()
        finally:
            conn.close()
    return get_task(task_id)


def get_task(task_id: str) -> dict | None:
    with DB_LOCK:
        conn = get_connection()
        try:
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            return _row_to_dict(row)
        finally:
            conn.close()


def list_tasks(status: str | None = None, incident_id: str | None = None, limit: int = 50) -> list[dict]:
    query = "SELECT * FROM tasks"
    clauses = []
    params = []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if incident_id:
        clauses.append("incident_id = ?")
        params.append(incident_id)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY updated_at DESC LIMIT ?"
    params.append(limit)
    with DB_LOCK:
        conn = get_connection()
        try:
            rows = conn.execute(query, tuple(params)).fetchall()
            return [_row_to_dict(row) for row in rows]
        finally:
            conn.close()


def complete_task(task_id: str) -> dict | None:
    now = time.time()
    with DB_LOCK:
        conn = get_connection()
        try:
            conn.execute(
                "UPDATE tasks SET status = ?, updated_at = ?, completed_at = ? WHERE id = ?",
                ("COMPLETED", now, now, task_id),
            )
            conn.commit()
        finally:
            conn.close()
    return get_task(task_id)


def create_agent_run(
    incident_id: str,
    request_id: str,
    agent_name: str,
    step_name: str,
    status: str,
    input_payload: dict | None,
    output_payload: dict | None,
    message: str,
) -> int:
    now = time.time()
    with DB_LOCK:
        conn = get_connection()
        try:
            cursor = conn.execute(
                """
                INSERT INTO agent_runs (
                    incident_id, request_id, agent_name, step_name, status,
                    input_json, output_json, message, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    request_id,
                    agent_name,
                    step_name,
                    status,
                    _json(input_payload),
                    _json(output_payload),
                    message,
                    now,
                ),
            )
            conn.commit()
            return int(cursor.lastrowid)
        finally:
            conn.close()


def list_agent_runs(incident_id: str | None = None, limit: int = 25) -> list[dict]:
    query = "SELECT * FROM agent_runs"
    params = []
    if incident_id:
        query += " WHERE incident_id = ?"
        params.append(incident_id)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with DB_LOCK:
        conn = get_connection()
        try:
            rows = conn.execute(query, tuple(params)).fetchall()
            return [_row_to_dict(row) for row in rows]
        finally:
            conn.close()


init_db()
