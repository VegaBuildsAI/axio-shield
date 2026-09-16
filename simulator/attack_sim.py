#!/usr/bin/env python3
"""Simulador determinista y local de AXIO Shield.

El ejecutor solo permite HTTP hacia localhost/127.0.0.1 y solo publica eventos
tipados en /ingest. No usa LLM, shell, exploits, credenciales ni Internet.

Ejemplos:
    python -m simulator.attack_sim baseline --url http://127.0.0.1:8000
    python -m simulator.attack_sim injection --url http://127.0.0.1:8000
    python -m simulator.attack_sim swarm --sessions 3 --url http://127.0.0.1:8000
    python -m simulator.attack_sim all --no-sleep --json
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from simulator.attacker_agents.director import AttackDirector, RunResult
from simulator.evaluator import evaluate
from simulator.engine.scope_guard import ScopeViolation


def _print_result(result: RunResult) -> None:
    rules = [
        rule
        for observation in result.observations
        for rule in observation.get("matched_rules", [])
    ]
    unique_rules = sorted(set(rules))
    evaluation = evaluate(result)
    print(
        f"{result.scenario_id}: acciones={len(result.ground_truth)} "
        f"reglas={unique_rules or ['none']} "
        f"canary_exfiltrated={result.canary_exfiltrated} "
        f"pass={evaluation.passed}"
    )


def _result_json(result: RunResult) -> dict[str, Any]:
    return {
        "scenario_id": result.scenario_id,
        "seed": result.seed,
        "observations": result.observations,
        "ground_truth": result.ground_truth,
        "canary_exfiltrated": result.canary_exfiltrated,
        "evaluation": evaluate(result).as_dict(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AXIO Shield local deterministic attack lab")
    parser.add_argument(
        "scenario",
        choices=[
            "baseline", "injection", "ai_browser", "swarm", "tool_poisoning",
            "memory_poisoning", "identity_abuse", "chain", "adaptive", "all",
            "objectives", "enumeration", "credential_harvest", "lateral_movement",
            "privilege_escalation", "persistence", "ad_killchain",
        ],
    )
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--sessions", type=int, default=3)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--no-sleep", action="store_true", help="no esperar entre acciones")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    try:
        results: list[RunResult] = []
        if args.scenario in ("baseline", "all"):
            results.append(AttackDirector(args.url, "S0-baseline", args.seed, not args.no_sleep).run_baseline())
        if args.scenario in ("injection", "all"):
            results.append(AttackDirector(args.url, "S1-direct-goal-hijack", args.seed, not args.no_sleep).run_injection())
        if args.scenario in ("ai_browser", "all"):
            results.append(AttackDirector(args.url, "S3-ai-browser", args.seed, not args.no_sleep).run_ai_browser())
        if args.scenario in ("swarm", "all"):
            results.append(AttackDirector(args.url, "S7-swarm-dead-drop", args.seed, not args.no_sleep).run_swarm(args.sessions))
        if args.scenario in ("tool_poisoning", "all"):
            results.append(AttackDirector(args.url, "S8-tool-poisoning", args.seed, not args.no_sleep).run_tool_poisoning())
        if args.scenario in ("memory_poisoning", "all"):
            results.append(AttackDirector(args.url, "S9-memory-poisoning", args.seed, not args.no_sleep).run_memory_poisoning())
        if args.scenario in ("identity_abuse", "all"):
            results.append(AttackDirector(args.url, "S10-identity-abuse", args.seed, not args.no_sleep).run_identity_abuse())
        if args.scenario in ("chain", "all"):
            results.append(AttackDirector(args.url, "S11-multistage-chain", args.seed, not args.no_sleep).run_chain())
        if args.scenario in ("adaptive", "all"):
            results.append(AttackDirector(args.url, "S12-adaptive-rotation", args.seed, not args.no_sleep).run_adaptive())
        if args.scenario in ("objectives", "all"):
            results.append(AttackDirector(args.url, "S13-objective-attack", args.seed, not args.no_sleep).run_objectives())
        if args.scenario in ("enumeration", "all"):
            results.append(AttackDirector(args.url, "S14-recon", args.seed, not args.no_sleep).run_enumeration())
        if args.scenario in ("credential_harvest", "all"):
            results.append(AttackDirector(args.url, "S15-cred", args.seed, not args.no_sleep).run_credential_harvest())
        if args.scenario in ("lateral_movement", "all"):
            results.append(AttackDirector(args.url, "S16-lateral", args.seed, not args.no_sleep).run_lateral_movement())
        if args.scenario in ("privilege_escalation", "all"):
            results.append(AttackDirector(args.url, "S17-privesc", args.seed, not args.no_sleep).run_privilege_escalation())
        if args.scenario in ("persistence", "all"):
            results.append(AttackDirector(args.url, "S18-persistence", args.seed, not args.no_sleep).run_persistence())
        if args.scenario in ("ad_killchain", "all"):
            results.append(AttackDirector(args.url, "S19-ad-chain", args.seed, not args.no_sleep).run_ad_killchain())
    except (ScopeViolation, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"simulador detenido: {exc}", file=sys.stderr)
        return 2

    if args.as_json:
        print(json.dumps([_result_json(result) for result in results], indent=2, ensure_ascii=False))
    else:
        print(f"AXIO Shield · simulador local → {args.url}")
        for result in results:
            _print_result(result)
        print("Listo. Revisá el dashboard y /api/audit/verify.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
