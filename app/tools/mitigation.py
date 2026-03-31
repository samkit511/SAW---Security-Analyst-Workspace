def mitigate(threat: dict, context: dict) -> list:
    """
    Idempotent mitigation actions.
    Ensures 'applied_actions' is mutated in-place for persistence.
    """
    applied = set(context.get("applied_actions", set()))
    threat_type = threat.get("threat_type") or threat.get("type", "Unknown")
    target_ip = context.get("ip", "unknown")
    confidence = float(context.get("confidence", 0.0))
    escalated = bool(context.get("escalated", False))
    
    actions = []
    action_keys = []

    def add_action(name, impact, target_aware=True):
        action_key = f"{name}:{target_ip}" if target_aware else name
        if action_key not in applied:
            actions.append({"action": name, "impact": impact})
            applied.add(action_key)
            action_keys.append(action_key)

    if threat_type == "SQL Injection":
        if escalated or confidence >= 0.78:
            add_action("Blocked IP", "HIGH", target_aware=True)
        else:
            add_action("Flagged IP For Review", "MEDIUM", target_aware=True)
        add_action("Enabled SQLi WAF Filter", "MEDIUM", target_aware=False)
    elif threat_type == "XSS":
        add_action("Sanitized payload", "MEDIUM", target_aware=True)
        add_action("Enabled XSS WAF rule", "MEDIUM", target_aware=False)
    elif threat_type == "Brute Force":
        add_action("Rate limit applied via API gateway", "HIGH", target_aware=True)
    elif threat_type == "Path Traversal":
        add_action("Blocked suspicious file access", "HIGH", target_aware=True)
        add_action("Enabled path traversal WAF rule", "MEDIUM", target_aware=False)

    if escalated:
        add_action("Temporary IP ban (auto escalation)", "HIGH", target_aware=True)
    
    return {
        "actions": actions,
        "actions_count": len(actions),
        "action_keys": action_keys,
        "enforcement_scope": "control_plane_demo",
    }
