from app.agents.specter import Specter
from app.core.event_bus import EventBus
from app.models.events import AttackerProfile, Incident, Urgency


def _inc(matched, extra):
    return Incident(session_id="s1", kind="xhr", matched_rules=matched,
                    urgency=Urgency.WATCH, evidence={"extra": extra, "features": {}})


async def test_cross_tenant_without_credential():
    s = Specter(EventBus())
    inc = _inc([], {"source_tenant": "a", "requested_tenant": "b", "credential_material": "never-sent"})
    await s.enrich(inc)
    assert inc.identity_verdict
    assert any(f["type"] == "cross_tenant" for f in inc.identity_verdict["findings"])


async def test_a2a_spoof_sets_profile():
    s = Specter(EventBus())
    inc = _inc(["agent.a2a_spoof"], {})
    await s.enrich(inc)
    assert inc.attacker_profile == AttackerProfile.A2A_HOSTILE
    assert inc.identity_verdict["identity_verified"] is False


async def test_identity_family_labels_owned():
    s = Specter(EventBus())
    inc = _inc(["identity.session_token_access", "identity.api_key_access"], {})
    await s.enrich(inc)
    assert any(f["type"] == "identity_abuse" for f in inc.identity_verdict["findings"])


async def test_unverified_agent_id_challenged():
    s = Specter(EventBus())
    inc = _inc([], {"agent_id": "attacker.unknown.agent"})
    await s.enrich(inc)
    assert inc.identity_verdict["findings"][0]["type"] == "a2a_spoof"


async def test_clean_incident_no_verdict():
    s = Specter(EventBus())
    inc = _inc(["prompt_injection.instruction_override"], {})
    await s.enrich(inc)
    assert inc.identity_verdict is None
