"""Director determinista que compone los agentes del primer incremento."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from simulator.attacker_agents.base_attacker import AttackerContext
from simulator.attacker_agents.browser_agent import BrowserAgent
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
from simulator.engine.action_executor import AttackAction, ActionExecutor
from simulator.engine.deterministic_clock import DeterministicClock
from simulator.engine.scope_guard import ScopeGuard
from simulator.engine.state_machine import AttackPhase
from simulator.ground_truth.action_log import GroundTruthLog, GroundTruthRecord
from simulator.targets.synthetic_target import SyntheticTarget


@dataclass
class RunResult:
    scenario_id: str
    seed: int
    observations: list[dict[str, Any]]
    ground_truth: list[dict[str, Any]]
    canary_exfiltrated: bool


class AttackDirector:
    def __init__(self, base_url: str, scenario_id: str, seed: int = 42, live: bool = True) -> None:
        ground_truth = GroundTruthLog()
        context = AttackerContext(
            scenario_id=scenario_id,
            seed=seed,
            executor=ActionExecutor(base_url, ScopeGuard()),
            clock=DeterministicClock(start=1_700_000_000.0 + seed, live=live),
            ground_truth=ground_truth,
        )
        self.context = context
        self.collector = LocalExfilCollector()

    def run_baseline(self) -> RunResult:
        observations: list[dict[str, Any]] = []
        sid = f"s_{self.context.seed:08d}_baseline"
        events = (
            ("page_load", "/portal/", {}, "baseline.page_load.v1"),
            ("form_submit", "/portal/", {"form_fill_ms": 4200, "field_count": 2}, "baseline.login.v1"),
            ("form_submit", "/portal/", {"form_fill_ms": 9000, "field_count": 3}, "baseline.transfer.v1"),
        )
        for index, (kind, path, features, fixture_id) in enumerate(events, start=1):
            action = AttackAction(
                action_id=f"{self.context.scenario_id}:baseline:{index}",
                attacker_id="BASELINE_USER",
                session_id=sid,
                phase=AttackPhase.RECON.value,
                action_type="emit_event",
                route="/ingest",
                fixture_id=fixture_id,
                scheduled_at=self.context.clock.tick(0.05 if index > 1 else 0.0),
                event={
                    "session_id": sid,
                    "kind": kind,
                    "path": path,
                    "ua": "Mozilla/5.0 (Windows NT 10.0) Chrome/125 Safari/537.36",
                    "features": features,
                    "extra": {"simulator": True, "fixture_id": fixture_id},
                },
            )
            observation = self.context.executor.execute(action)
            observations.append(observation)
            self.context.ground_truth.append(
                GroundTruthRecord(
                    action_id=action.action_id,
                    scenario_id=self.context.scenario_id,
                    attacker_id=action.attacker_id,
                    session_id=sid,
                    phase=action.phase,
                    fixture_id=fixture_id,
                    observation=observation,
                )
            )
        return self._result(observations)

    def run_injection(self) -> RunResult:
        sid = f"s_{self.context.seed:08d}_injection"
        observations = [InjectionAgent(self.context).run(sid)]
        observations.append(ExfiltrationAgent(self.context).run(sid, self.collector))
        return self._result(observations)

    def run_ai_browser(self) -> RunResult:
        sid = f"s_{self.context.seed:08d}_browser"
        return self._result(BrowserAgent(self.context).run(sid))

    def run_swarm(self, sessions: int = 3) -> RunResult:
        if sessions < 3 or sessions > 12:
            raise ValueError("swarm sessions debe estar entre 3 y 12")
        observations: list[dict[str, Any]] = []
        for index in range(sessions):
            sid = f"s_{self.context.seed:08d}_swarm_{index + 1:02d}"
            observations.append(InjectionAgent(self.context).run(sid))
            observations.append(self._emit_dead_drop(sid, index + 1))
        return self._result(observations)

    def run_tool_poisoning(self) -> RunResult:
        sid = f"s_{self.context.seed:08d}_tool"
        return self._result([ToolPoisoningAgent(self.context).run(sid)])

    def run_memory_poisoning(self) -> RunResult:
        sid = f"s_{self.context.seed:08d}_memory"
        return self._result([MemoryPoisoningAgent(self.context).run(sid)])

    def run_identity_abuse(self) -> RunResult:
        sid = f"s_{self.context.seed:08d}_identity"
        return self._result([IdentityAbuseAgent(self.context).run(sid)])

    def run_chain(self) -> RunResult:
        sid = f"s_{self.context.seed:08d}_chain"
        return self._result(ChainAgent(self.context).run(sid))

    def run_adaptive(self) -> RunResult:
        """Cambia de variante una sola vez si el backend marca la primera señal."""
        sid = f"s_{self.context.seed:08d}_adaptive"
        agent = ChainAgent(self.context)
        observations = [agent.emit(
            session_id=sid,
            action_suffix="adaptive:initial",
            attacker_id="ADAPTIVE_AGENT",
            phase=AttackPhase.DELIVERY,
            fixture_id="adaptive.initial.v1",
            features={"tool_poisoning_suspect": True},
            client_matches=["agent.tool_poisoning"],
            extra={"variant": "description_only", "adaptive_step": 1},
        )]
        if observations[0].get("matched_rules"):
            observations.append(agent.emit(
                session_id=sid,
                action_suffix="adaptive:variant-rotate",
                attacker_id="ADAPTIVE_AGENT",
                phase=AttackPhase.ADAPT,
                fixture_id="adaptive.variant_rotation.v1",
                features={"memory_poisoning_suspect": True, "c2_migration": True},
                client_matches=["agent.memory_poisoning", "agent.c2_migration"],
                extra={"variant": "shared-context-marker", "adaptive_step": 2},
            ))
        return self._result(observations)

    def run_objectives(self) -> RunResult:
        sid = f"s_{self.context.seed:08d}_objectives"
        observations = ObjectiveAgent(self.context).run(sid, SyntheticTarget(), self.collector)
        return self._result(observations)

    def run_enumeration(self) -> RunResult:
        sid = f"s_{self.context.seed:08d}_recon"
        return self._result([ReconAgent(self.context).run(sid)])

    def run_credential_harvest(self) -> RunResult:
        sid = f"s_{self.context.seed:08d}_credential"
        return self._result([CredentialAgent(self.context).run(sid)])

    def run_lateral_movement(self) -> RunResult:
        sid = f"s_{self.context.seed:08d}_lateral_primary"
        peer = f"s_{self.context.seed:08d}_lateral_peer"
        return self._result(LateralAgent(self.context).run(sid, peer))

    def run_privilege_escalation(self) -> RunResult:
        sid = f"s_{self.context.seed:08d}_privesc"
        return self._result([PrivescAgent(self.context).run(sid)])

    def run_persistence(self) -> RunResult:
        sid = f"s_{self.context.seed:08d}_persistence"
        return self._result([PersistenceAgent(self.context).run(sid)])

    def run_ad_killchain(self) -> RunResult:
        """Campaña AD-inspired en una sesión principal + peer lateral controlado."""
        sid = f"s_{self.context.seed:08d}_ad_chain"
        peer = f"s_{self.context.seed:08d}_ad_chain_peer"
        observations = [
            ReconAgent(self.context).run(sid),
            CredentialAgent(self.context).run(sid),
        ]
        observations.extend(LateralAgent(self.context).run(sid, peer))
        observations.extend([
            PrivescAgent(self.context).run(sid),
            PersistenceAgent(self.context).run(sid),
        ])
        return self._result(observations)

    def _emit_dead_drop(self, session_id: str, index: int) -> dict[str, Any]:
        action = AttackAction(
            action_id=f"{self.context.scenario_id}:swarm:deaddrop:{index}",
            attacker_id="SWARM_COORDINATOR",
            session_id=session_id,
            phase=AttackPhase.DELIVERY.value,
            action_type="emit_event",
            route="/ingest",
            fixture_id="swarm.dead_drop.v1",
            scheduled_at=self.context.clock.tick(0.3),
            event={
                "session_id": session_id,
                "kind": "form_submit",
                "path": "/portal/",
                "ua": "Mozilla/5.0 Chrome/125 Safari/537.36",
                "client_matches": ["swarm.deaddrop"],
                "features": {"deaddrop_suspect": True, "field_count": 3, "entropy": 5.4},
                "extra": {"simulator": True, "fixture_id": "swarm.dead_drop.v1", "node_index": index},
            },
        )
        observation = self.context.executor.execute(action)
        self.context.ground_truth.append(
            GroundTruthRecord(
                action_id=action.action_id,
                scenario_id=self.context.scenario_id,
                attacker_id=action.attacker_id,
                session_id=action.session_id,
                phase=action.phase,
                fixture_id=action.fixture_id,
                observation=observation,
            )
        )
        return observation

    def _result(self, observations: list[dict[str, Any]]) -> RunResult:
        return RunResult(
            scenario_id=self.context.scenario_id,
            seed=self.context.seed,
            observations=observations,
            ground_truth=self.context.ground_truth.export(),
            canary_exfiltrated=self.collector.has_receipts(),
        )
