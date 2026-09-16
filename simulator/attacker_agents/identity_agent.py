"""Abuso de identidad sintética: cruce de tenant sin credenciales reales."""
from __future__ import annotations

from simulator.attacker_agents.metadata_signal_agent import MetadataSignalAgent
from simulator.engine.state_machine import AttackPhase


class IdentityAbuseAgent(MetadataSignalAgent):
    name = "IDENTITY_ABUSE_AGENT"

    def run(self, session_id: str) -> dict:
        return self.emit(
            session_id=session_id,
            action_suffix="identity-abuse:cross-tenant",
            attacker_id=self.name,
            phase=AttackPhase.EXPLOITATION,
            fixture_id="identity_abuse.cross_tenant.v1",
            features={"cross_tenant_suspect": True},
            client_matches=["agent.a2a_spoof"],
            extra={
                "source_tenant": "tenant_alpha_fixture",
                "requested_tenant": "tenant_beta_fixture",
                "credential_material": "never-sent",
            },
        )
