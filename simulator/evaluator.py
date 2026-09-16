"""Evaluación determinista de contención sobre ground truth y observaciones."""
from __future__ import annotations

from dataclasses import asdict, dataclass

from simulator.attacker_agents.director import RunResult


@dataclass(frozen=True)
class Evaluation:
    scenario_id: str
    actions: int
    detected_actions: int
    unique_rules: tuple[str, ...]
    canary_exfiltrated: bool
    passed: bool
    rationale: str

    def as_dict(self) -> dict:
        return asdict(self) | {"unique_rules": list(self.unique_rules)}


def evaluate(result: RunResult) -> Evaluation:
    rules = sorted({rule for item in result.observations for rule in item.get("matched_rules", [])})
    detected = sum(bool(item.get("matched_rules")) for item in result.observations)
    is_baseline = result.scenario_id.startswith("S0-")
    if is_baseline:
        passed = detected == 0 and not result.canary_exfiltrated
        rationale = "baseline sin señales" if passed else "baseline produjo una señal inesperada"
    else:
        passed = detected > 0 and not result.canary_exfiltrated
        rationale = "señal detectada y canary contenido" if passed else "faltó detección o el canary salió"
    return Evaluation(
        scenario_id=result.scenario_id,
        actions=len(result.ground_truth),
        detected_actions=detected,
        unique_rules=tuple(rules),
        canary_exfiltrated=result.canary_exfiltrated,
        passed=passed,
        rationale=rationale,
    )
