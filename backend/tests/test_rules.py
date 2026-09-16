from app.detection.rules import map_owasp, score_event, ua_matches
from app.models.events import IngestEvent


def test_baseline_no_match():
    ev = IngestEvent(session_id="s1", kind="form_submit",
                     ua="Mozilla/5.0 Chrome/125", features={"form_fill_ms": 5000})
    score, matched = score_event(ev)
    assert score == 0.0
    assert matched == []


def test_prompt_injection_scores_high():
    ev = IngestEvent(session_id="s1",
                     client_matches=["prompt_injection.instruction_override", "prompt_injection.exfil"])
    score, matched = score_event(ev)
    assert score > 0.85
    assert "prompt_injection.instruction_override" in matched
    code, _ = map_owasp(matched)
    assert code == "ASI02"


def test_ai_browser_ua_detected():
    assert "ai_browser.ua" in ua_matches("Mozilla/5.0 (compatible; PerplexityBot/1.0)")
    assert "automation.client" in ua_matches("python-requests/2.31")
    assert ua_matches("Mozilla/5.0 Chrome/125 Safari/537.36") == []


def test_fast_form_fill_flags_timing():
    ev = IngestEvent(session_id="s1", features={"form_fill_ms": 120})
    score, matched = score_event(ev)
    assert "automation.timing" in matched
    assert score > 0


def test_deaddrop_feature():
    ev = IngestEvent(session_id="s1", features={"deaddrop_suspect": True})
    _, matched = score_event(ev)
    assert "swarm.deaddrop" in matched


def test_agentic_poisoning_and_identity_features_are_detected():
    ev = IngestEvent(
        session_id="s1",
        features={
            "tool_poisoning_suspect": True,
            "memory_poisoning_suspect": True,
            "cross_tenant_suspect": True,
            "c2_migration": True,
        },
        client_matches=["agent.a2a_spoof"],
    )
    score, matched = score_event(ev)
    assert score > 0.95
    assert {
        "agent.tool_poisoning",
        "agent.memory_poisoning",
        "identity.cross_tenant",
        "agent.c2_migration",
        "agent.a2a_spoof",
    }.issubset(matched)


def test_scope_escape_maps_to_agentic_execution_risk():
    ev = IngestEvent(session_id="s1", features={"scope_escape_attempt": True})
    _, matched = score_event(ev)
    assert map_owasp(matched)[0] == "ASI05"


def test_objective_access_signals_are_detected():
    ev = IngestEvent(
        session_id="s1",
        features={
            "credential_access_attempt": True,
            "session_token_access_attempt": True,
            "api_key_access_attempt": True,
            "database_query_abuse": True,
            "privilege_escalation_attempt": True,
            "high_impact_tool_call": True,
            "exfiltration_attempt": True,
        },
    )
    score, matched = score_event(ev)
    assert score > 0.99
    assert "identity.credential_access" in matched
    assert "identity.api_key_access" in matched
    assert "data.database_query_abuse" in matched
    assert "tool.high_impact_call" in matched
