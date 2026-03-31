import os

EXECUTE_THRESHOLD = float(os.getenv("ASA_EXECUTE_THRESHOLD", "2.5"))
OBSERVE_THRESHOLD = float(os.getenv("ASA_OBSERVE_THRESHOLD", "1.5"))


def decision_engine(threat: dict, escalated: bool = False) -> dict:
    """
    Unified Risk-Driven Decision Engine.
    Scales: [0, 3] Risk Score.
    """
    base_risk = threat.get("risk_score", 0.0)
    behavior_adjustment = 0.5 if threat.get("behavior") == "Aggressive Attacker" else 0.0
    risk = round(base_risk + behavior_adjustment, 2)
    
    if escalated or risk >= EXECUTE_THRESHOLD:
        return {
            "decision": "EXECUTE",
            "decision_reason": "Escalation override (persistent attacker)" if escalated else f"Risk score {risk} exceeds execution threshold ({EXECUTE_THRESHOLD})",
            "safe_to_execute": True,
            "safety_reason": "High confidence or repeated attack pattern requires immediate mitigation to protect system integrity.",
            "system_confidence": "HIGH",
            "evaluated_risk_score": risk,
            "base_risk_score": base_risk,
            "behavior_adjustment": behavior_adjustment,
        }
    if risk >= OBSERVE_THRESHOLD:
        return {
            "decision": "OBSERVE",
            "decision_reason": f"Risk score {risk} in observation range ({OBSERVE_THRESHOLD}-{EXECUTE_THRESHOLD})",
            "safe_to_execute": False,
            "safety_reason": "Confidence insufficient for automated block; logging for human review and incident analysis.",
            "system_confidence": "MEDIUM",
            "evaluated_risk_score": risk,
            "base_risk_score": base_risk,
            "behavior_adjustment": behavior_adjustment,
        }

    return {
        "decision": "IGNORE",
        "decision_reason": f"Risk score {risk} below impact threshold ({OBSERVE_THRESHOLD})",
        "safe_to_execute": False,
        "safety_reason": "Signal categorized as low-risk or false positive; no action required.",
        "system_confidence": "LOW",
        "evaluated_risk_score": risk,
        "base_risk_score": base_risk,
        "behavior_adjustment": behavior_adjustment,
    }
