def suggest_action(score, event_type):
    """
    Suggests an action based on the risk score.
    """
    if score >= 80:
        return "BLOCK IMMEDIATELY"
    elif score >= 50:
        return "ESCALATE TO TIER 2"
    else:
        return "MONITOR"