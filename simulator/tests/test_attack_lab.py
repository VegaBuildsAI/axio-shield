from __future__ import annotations

import pytest

from simulator.attacker_agents.base_attacker import AttackerContext
from simulator.attacker_agents.exfiltration_agent import ExfiltrationAgent
from simulator.attacker_agents.injection_agent import InjectionAgent
from simulator.attacker_agents.tool_poison_agent import ToolPoisoningAgent
from simulator.attacker_agents.memory_poison_agent import MemoryPoisoningAgent
from simulator.attacker_agents.identity_agent import IdentityAbuseAgent
from simulator.attacker_agents.chain_agent import ChainAgent
from simulator.attacker_agents.objective_agent import ObjectiveAgent
from simulator.attacker_agents.recon_agent import ReconAgent
from simulator.attacker_agents.credential_agent import CredentialAgent
from simulator.attacker_agents.lateral_agent import LateralAgent
from simulator.attacker_agents.privesc_agent import PrivescAgent
from simulator.attacker_agents.persistence_agent import PersistenceAgent
from simulator.collectors.local_exfil_collector import LocalExfilCollector
from simulator.engine.deterministic_clock import DeterministicClock
from simulator.engine.state_machine import AttackPhase
from simulator.ground_truth.action_log import GroundTruthLog
from simulator.engine.scope_guard import ScopeGuard, ScopeViolation
from simulator.evaluator import evaluate
from simulator.attacker_agents.director import RunResult
from simulator.targets.synthetic_target import SyntheticTarget


class FakeExecutor:
    def execute(self, action):
        assert action.action_type == "emit_event"
        assert action.route == "/ingest"
        assert action.event.get("extra", {}).get("simulator") is True
        return {"ok": True, "matched_rules": action.event.get("client_matches", [])}


def test_clock_is_reproducible_without_sleep() -> None:
    first = DeterministicClock(start=100.0, live=False)
    second = DeterministicClock(start=100.0, live=False)
    assert [first.tick(0.3), first.tick(0.15)] == [second.tick(0.3), second.tick(0.15)]


def test_scope_guard_rejects_external_targets() -> None:
    guard = ScopeGuard()
    with pytest.raises(ScopeViolation):
        guard.validate_base_url("https://example.com")
    with pytest.raises(ScopeViolation):
        guard.validate_base_url("http://192.0.2.10:8000")


def test_scope_guard_rejects_path_traversal() -> None:
    with pytest.raises(ScopeViolation):
        ScopeGuard().validate_route("http://127.0.0.1:8000", "/../admin")


def test_canary_collector_stays_in_memory() -> None:
    collector = LocalExfilCollector()
    assert collector.has_receipts() is False
    collector.receive("AXIO_CANARY_DOCUMENT_001", "s_test", "local-test-only")
    assert collector.has_receipts() is True
    assert collector.receipts[0].channel == "local-test-only"


def test_injection_agent_is_deterministic_and_metadata_only() -> None:
    context = AttackerContext(
        scenario_id="S-test",
        seed=7,
        executor=FakeExecutor(),
        clock=DeterministicClock(start=100.0, live=False),
        ground_truth=GroundTruthLog(),
    )
    observation = InjectionAgent(context).run("s_test")
    record = context.ground_truth.records[0]
    assert record.fixture_id == "goal_hijack.direct_visible.v1"
    assert record.phase == AttackPhase.DELIVERY.value
    assert observation["matched_rules"]
    assert "contenido" not in record.observation


def test_exfiltration_agent_does_not_record_blocked_canary() -> None:
    context = AttackerContext(
        scenario_id="S-test-exfil",
        seed=7,
        executor=FakeExecutor(),
        clock=DeterministicClock(start=100.0, live=False),
        ground_truth=GroundTruthLog(),
    )
    collector = LocalExfilCollector()
    ExfiltrationAgent(context).run("s_test", collector)
    assert collector.has_receipts() is False


def _context() -> AttackerContext:
    return AttackerContext(
        scenario_id="S-test-extra",
        seed=9,
        executor=FakeExecutor(),
        clock=DeterministicClock(start=100.0, live=False),
        ground_truth=GroundTruthLog(),
    )


def test_new_agents_emit_only_typed_local_metadata() -> None:
    context = _context()
    observations = [
        ToolPoisoningAgent(context).run("s_tool"),
        MemoryPoisoningAgent(context).run("s_memory"),
        IdentityAbuseAgent(context).run("s_identity"),
    ]
    assert all(item["ok"] for item in observations)
    assert [record.fixture_id for record in context.ground_truth.records] == [
        "tool_poisoning.registry_metadata.v1",
        "memory_poisoning.shared_context.v1",
        "identity_abuse.cross_tenant.v1",
    ]
    assert all(record.observation["ok"] for record in context.ground_truth.records)


def test_chain_has_finite_reproducible_steps() -> None:
    context = _context()
    observations = ChainAgent(context).run("s_chain")
    assert len(observations) == 5
    assert [record.phase for record in context.ground_truth.records] == [
        "RECON", "DELIVERY", "PERSISTENCE", "EXPLOITATION", "COMMAND_AND_CONTROL",
    ]


def test_evaluator_requires_detection_and_no_canary_exfiltration() -> None:
    safe = RunResult("S0-baseline", 1, [{"matched_rules": []}], [{}], False)
    unsafe = RunResult("S11-chain", 1, [{"matched_rules": ["agent.tool_poisoning"]}], [{}], False)
    leaked = RunResult("S11-chain", 1, [{"matched_rules": ["agent.tool_poisoning"]}], [{}], True)
    assert evaluate(safe).passed is True
    assert evaluate(unsafe).passed is True
    assert evaluate(leaked).passed is False


def test_objective_agent_reaches_only_synthetic_target_and_contains_canary() -> None:
    context = _context()
    collector = LocalExfilCollector()
    observations = ObjectiveAgent(context).run("s_objectives", SyntheticTarget(), collector)
    assert len(observations) == 7
    assert collector.has_receipts() is False
    assert all(record.observation["ok"] for record in context.ground_truth.records)
    assert all(
        record.metadata["objective_result"]["raw_values_included"] is False
        for record in context.ground_truth.records
    )


def test_recon_agent_matches_ad_lab_contract() -> None:
    context = _context()
    observation = ReconAgent(context).run("s_recon")
    record = context.ground_truth.records[0]
    assert record.fixture_id == "recon.enumeration.bloodhound.v1"
    assert record.phase == AttackPhase.RECON.value
    assert observation["matched_rules"]
    assert record.metadata["phase"] == "recon"
    assert record.metadata["target"] == "/portal/directory"


def test_credential_agent_matches_ad_lab_contract() -> None:
    context = _context()
    observation = CredentialAgent(context).run("s_credential")
    record = context.ground_truth.records[0]
    assert record.fixture_id == "credential.harvest.kerberoast_asrep.v1"
    assert record.phase == AttackPhase.EXPLOITATION.value
    assert observation["matched_rules"]
    assert record.metadata["phase"] == "credential_access"


def test_lateral_agent_reuses_same_token_and_identity_across_two_sessions() -> None:
    context = _context()
    observations = LateralAgent(context).run("s_lateral_1", "s_lateral_2")
    assert len(observations) == 2
    assert all(observation["matched_rules"] for observation in observations)
    assert [record.fixture_id for record in context.ground_truth.records] == [
        "lateral.pass_the_hash.wkstn1.v1", "lateral.pass_the_hash.wkstn2.v1",
    ]
    assert len({record.session_id for record in context.ground_truth.records}) == 2
    assert len({record.metadata["token"] for record in context.ground_truth.records}) == 1
    assert len({record.metadata["identity"] for record in context.ground_truth.records}) == 1


def test_privesc_agent_matches_ad_lab_contract() -> None:
    context = _context()
    observation = PrivescAgent(context).run("s_privesc")
    record = context.ground_truth.records[0]
    assert record.fixture_id == "privesc.dcsync_acl.v1"
    assert record.phase == AttackPhase.EXPLOITATION.value
    assert observation["matched_rules"]
    assert record.metadata["target"] == "/portal/admin"


def test_persistence_agent_matches_ad_lab_contract() -> None:
    context = _context()
    observation = PersistenceAgent(context).run("s_persistence")
    record = context.ground_truth.records[0]
    assert record.fixture_id == "persistence.golden_ticket.rogue_rule.v1"
    assert record.phase == AttackPhase.PERSISTENCE.value
    assert observation["matched_rules"]
    assert record.metadata["phase"] == "persistence"
