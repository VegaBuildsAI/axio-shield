"""Integración: evento -> SENTINEL -> ORACLE -> TRACKER -> HERALD."""
from app.models.events import AttackerProfile, IngestEvent, Urgency

HUMAN_UA = "Mozilla/5.0 Chrome/125 Safari/537.36"
BOT_UA = "Mozilla/5.0 (compatible; PerplexityBot/1.0)"


async def test_baseline_creates_no_incident(system):
    ev = IngestEvent(session_id="s1", kind="form_submit", ua=HUMAN_UA,
                     features={"form_fill_ms": 5000, "field_count": 2})
    await system.sentinel.handle(ev)
    await system.bus.drain()
    assert system.store.list_incidents() == []


async def test_injection_classified_asi02(system):
    ev = IngestEvent(session_id="s1", kind="form_submit", ua=HUMAN_UA,
                     client_matches=["prompt_injection.instruction_override", "prompt_injection.exfil"])
    await system.sentinel.handle(ev)
    await system.bus.drain()
    incs = system.store.list_incidents()
    assert len(incs) == 1
    assert incs[0].owasp == "ASI02"
    assert incs[0].urgency in (Urgency.CONTAIN, Urgency.ELIMINATE)
    # HERALD emitió alerta al dashboard
    assert any(b["type"] == "incident" for b in system.broadcasts)


async def test_ai_browser_profiled(system):
    ev = IngestEvent(session_id="s1", kind="form_submit", ua=BOT_UA,
                     features={"form_fill_ms": 120})
    await system.sentinel.handle(ev)
    await system.bus.drain()
    inc = system.store.list_incidents()[0]
    assert inc.attacker_profile in (AttackerProfile.HUMAN_AI, AttackerProfile.SWARM)


async def test_swarm_detected_across_sessions(system):
    for i in range(3):
        ev = IngestEvent(session_id=f"swarm_{i}", kind="form_submit", ua=HUMAN_UA,
                         client_matches=["swarm.deaddrop"],
                         features={"deaddrop_suspect": True})
        await system.sentinel.handle(ev)
    await system.bus.drain()
    incs = system.store.list_incidents()
    coordinated = [i for i in incs if i.swarm and i.swarm.coordinated]
    assert coordinated, "TRACKER debió detectar coordinación de swarm"
    latest = coordinated[-1]
    assert latest.attacker_profile == AttackerProfile.SWARM
    assert len(latest.swarm.session_ids) >= 2
    assert set(latest.swarm.roles.values()) & {"exploiter", "exfiltrator", "C2_manager", "recruiter"}


async def test_human_gate_containment(system):
    ev = IngestEvent(session_id="s1", client_matches=["prompt_injection.instruction_override"])
    await system.sentinel.handle(ev)
    await system.bus.drain()
    inc = system.store.list_incidents()[0]
    assert inc.status == "open"
    updated = await system.lockdown.apply(inc.id, "block_session", "analyst")
    assert updated.status == "contained"
    assert updated.actions[0]["simulated"] is True
    # queda registrado en el audit log
    assert any(r["action"] == "human_gate_action" for r in system.scribe.export())
