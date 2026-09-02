"""Convenience builders for envelopes and permissions."""

from __future__ import annotations

from typing import Optional

from .core import ActionSchema, Authority, Permission, RestrictPolicy, RiskSignal
from .envelope import AuthorityEnvelope


def make_permission(name: str, scope: str = "*", max_budget: Optional[int] = None) -> Permission:
    return Permission(name=name, scope=scope, max_budget=max_budget)


def build_demo_envelope() -> AuthorityEnvelope:
    research = Authority(permissions={
        make_permission("research"), make_permission("read", "web"), make_permission("read", "docs"),
    })
    coder = Authority(permissions={
        make_permission("code", "write"), make_permission("code", "test"),
        make_permission("read", "repo"),
    })
    deployer = Authority(permissions={
        make_permission("deploy", "staging", max_budget=5), make_permission("read", "logs"),
    })
    approver = Authority(permissions={make_permission("approve", "high-risk")})

    return AuthorityEnvelope(
        objective=(
            "Build a secure multi-agent governance prototype and keep the system inside "
            "the declared authority envelope"
        ),
        agent_authorities={
            "agent_research": research,
            "agent_coder": coder,
            "agent_deploy": deployer,
            "agent_approver": approver,
        },
        allowed_delegations={
            "research": {"coder"},
            "coder": {"deploy"},
            "deploy": set(),
            "approver": set(),
        },
        agent_roles={
            "agent_research": "research",
            "agent_coder": "coder",
            "agent_deploy": "deploy",
            "agent_approver": "approver",
        },
        hard_denials={"delete_production", "exfiltrate_secrets", "disable_chainmail"},
        max_fleet_steps=50,
        require_human_on={RiskSignal.AUTHORITY_ABUSE, RiskSignal.OBJECTIVE_MISMATCH},
        restrict_policy=RestrictPolicy.TTL_STEPS,
        restrict_ttl_steps=3,
        restrict_step_budget=10,
        action_schemas={
            "deploy_service": ActionSchema(
                allowed_payload_keys=frozenset({"target", "version", "dry_run"}),
                required_payload_keys=frozenset({"target"}),
                filesystem_path_fields=frozenset({"target"}),
                allow_nested_payload=False,
            ),
            "write_code": ActionSchema(
                allowed_payload_keys=frozenset({"file", "content", "mode"}),
                required_payload_keys=frozenset({"file"}),
                filesystem_path_fields=frozenset({"file"}),
                allow_nested_payload=False,
            ),
        },
    )
