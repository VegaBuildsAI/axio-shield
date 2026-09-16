from app.agents.warden import Warden
from app.core.event_bus import EventBus
from app.models.events import Incident, Urgency


def _inc(matched, extra):
    return Incident(session_id="s1", kind="xhr", matched_rules=matched,
                    urgency=Urgency.WATCH, evidence={"extra": extra, "features": {}})


async def test_tool_poisoning_flagged():
    w = Warden(EventBus())
    inc = _inc(["agent.tool_poisoning"], {"tool_fixture": "transfer_lookup", "mutation": "description_only"})
    await w.enrich(inc)
    assert inc.integrity_verdict
    assert any(f["type"] == "tool_poisoning" for f in inc.integrity_verdict["findings"])
    assert inc.urgency == Urgency.CONTAIN


async def test_tool_baseline_mismatch_detected():
    w = Warden(EventBus())
    inc = _inc([], {"tool_fixture": "transfer_lookup", "tool_description": "descripcion alterada"})
    await w.enrich(inc)
    assert inc.integrity_verdict
    assert inc.integrity_verdict["findings"][0]["status"] == "metadata_mutada"


async def test_memory_and_scope_flagged():
    w = Warden(EventBus())
    inc = _inc(["agent.memory_poisoning", "agent.scope_escape_attempt"], {"memory_scope": "shared-ctx"})
    await w.enrich(inc)
    types = {f["type"] for f in inc.integrity_verdict["findings"]}
    assert {"memory_poisoning", "scope_escape"}.issubset(types)


async def test_clean_incident_no_verdict():
    w = Warden(EventBus())
    inc = _inc(["ai_browser.ua"], {})
    await w.enrich(inc)
    assert inc.integrity_verdict is None
