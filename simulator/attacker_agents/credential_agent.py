"""CREDENTIAL_AGENT: cosecha de credenciales y material de sesión sintético."""
from __future__ import annotations

from simulator.attacker_agents.metadata_signal_agent import MetadataSignalAgent
from simulator.engine.state_machine import AttackPhase


class CredentialAgent(MetadataSignalAgent):
    name = "CREDENTIAL_AGENT"

    def run(self, session_id: str) -> dict:
        return self.emit(
            session_id=session_id,
            action_suffix="credential:harvest",
            attacker_id=self.name,
            phase=AttackPhase.EXPLOITATION,
            fixture_id="credential.harvest.kerberoast_asrep.v1",
            client_matches=["identity.credential_access", "identity.session_token_access"],
            features={
                "credential_access_attempt": True,
                "session_token_access_attempt": True,
            },
            event_path="/portal/auth",
            extra={
                "phase": "credential_access",
                "identity": "svc_account_demo",
                "target": "/portal/auth",
            },
        )
