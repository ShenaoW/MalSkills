from __future__ import annotations

from typing import Any

from ..models import SSOFinding

SCHEMA_VERSION = "sso-finding-v2"
REQUIRED_FINDING_FIELDS = (
    "producer",
    "artifact",
    "span",
    "category",
    "subtype",
    "matched_text",
    "attributes",
    "provenance",
)

SSO_CATEGORY_BY_SUBTYPE = {
    "direct_process_execution": "payload_execution",
    "shell_interpreter_execution": "payload_execution",
    "script_host_execution": "payload_execution",
    "dynamic_module_load": "payload_execution",
    "proxy_execution_or_lolbin_abuse": "payload_execution",
    "process_attach": "process_and_memory_manipulation",
    "cross_process_memory_read": "process_and_memory_manipulation",
    "cross_process_memory_write": "process_and_memory_manipulation",
    "remote_thread_or_async_execution": "process_and_memory_manipulation",
    "executable_memory_mapping": "process_and_memory_manipulation",
    "process_hollowing_or_image_replacement": "process_and_memory_manipulation",
    "startup_or_logon_persistence": "persistence_and_startup_control",
    "service_or_daemon_persistence": "persistence_and_startup_control",
    "scheduled_persistence": "persistence_and_startup_control",
    "event_triggered_persistence": "persistence_and_startup_control",
    "boot_chain_persistence": "persistence_and_startup_control",
    "identity_switch": "privilege_and_identity_manipulation",
    "privilege_adjustment": "privilege_and_identity_manipulation",
    "token_or_session_impersonation": "privilege_and_identity_manipulation",
    "group_or_acl_modification": "privilege_and_identity_manipulation",
    "boundary_bypass": "privilege_and_identity_manipulation",
    "password_or_hash_access": "credential_and_secret_access",
    "session_or_token_access": "credential_and_secret_access",
    "private_key_or_api_key_access": "credential_and_secret_access",
    "credential_decryption": "credential_and_secret_access",
    "authentication_input_capture": "credential_and_secret_access",
    "system_and_hardware_discovery": "host_and_environment_discovery",
    "identity_and_account_discovery": "host_and_environment_discovery",
    "process_and_service_discovery": "host_and_environment_discovery",
    "network_and_neighbor_discovery": "host_and_environment_discovery",
    "domain_or_org_discovery": "host_and_environment_discovery",
    "security_environment_discovery": "host_and_environment_discovery",
    "file_enumeration_and_location": "file_and_data_access",
    "content_read_and_parse": "file_and_data_access",
    "bulk_copy_and_archive": "file_and_data_access",
    "config_or_metadata_modification": "file_and_data_access",
    "deletion_or_overwrite": "file_and_data_access",
    "outbound_connection": "network_and_remote_communication",
    "listener_and_receive": "network_and_remote_communication",
    "tunneling_and_forwarding": "network_and_remote_communication",
    "proxy_or_route_manipulation": "network_and_remote_communication",
    "protocol_encapsulation_or_encrypted_comm": "network_and_remote_communication",
    "traffic_capture_and_observation": "network_and_remote_communication",
    "remote_login": "lateral_movement_and_remote_execution",
    "remote_command_execution": "lateral_movement_and_remote_execution",
    "remote_file_transfer": "lateral_movement_and_remote_execution",
    "remote_management_abuse": "lateral_movement_and_remote_execution",
    "cluster_or_cloud_node_control": "lateral_movement_and_remote_execution",
    "security_tool_impairment": "defense_evasion_and_anti_forensics",
    "logging_or_audit_suppression": "defense_evasion_and_anti_forensics",
    "policy_or_access_control_weakening": "defense_evasion_and_anti_forensics",
    "artifact_cleanup_or_timestomp": "defense_evasion_and_anti_forensics",
    "object_hiding_or_visibility_evasion": "defense_evasion_and_anti_forensics",
    "data_destruction": "impact_and_destruction",
    "data_encryption_or_locking": "impact_and_destruction",
    "recovery_impairment": "impact_and_destruction",
    "availability_disruption": "impact_and_destruction",
    "boot_or_low_level_destruction": "impact_and_destruction",
}

SSO_CATEGORIES = tuple(dict.fromkeys(SSO_CATEGORY_BY_SUBTYPE.values()))
SSO_SUBTYPES = tuple(SSO_CATEGORY_BY_SUBTYPE.keys())

DISALLOWED_LLM_ATTRIBUTE_KEYS = {
    "classification",
    "conclusion",
    "final_classification",
    "final_conclusion",
    "final_label",
    "final_verdict",
    "is_malicious",
    "label",
    "malicious",
    "malicious_patterns",
    "risk_classification",
    "risk_label",
    "suspicious_patterns",
    "verdict",
}
def canonical_sso_category(subtype: str, fallback: str) -> str:
    return SSO_CATEGORY_BY_SUBTYPE.get(subtype, fallback)


def infer_sso_category(subtype: str) -> str:
    return SSO_CATEGORY_BY_SUBTYPE.get(subtype, "unknown")


def sanitize_llm_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in attributes.items():
        normalized = key.strip().lower().replace("-", "_").replace(" ", "_")
        if normalized in DISALLOWED_LLM_ATTRIBUTE_KEYS:
            continue
        sanitized[key] = value
    return sanitized


def normalize_sso_finding(record: SSOFinding) -> SSOFinding:
    if not record.producer:
        raise ValueError("SSO finding is missing required field: producer")
    if not record.artifact_id or not record.artifact_path:
        raise ValueError("SSO finding is missing required field: artifact")
    if not record.category:
        raise ValueError("SSO finding is missing required field: category")
    if record.span is None:
        raise ValueError("SSO finding is missing required field: span")
    if not isinstance(record.attributes, dict):
        raise ValueError("SSO finding has invalid field: attributes")
    if not isinstance(record.provenance, dict):
        raise ValueError("SSO finding has invalid field: provenance")

    attributes = dict(record.attributes)
    if record.subtype not in SSO_CATEGORY_BY_SUBTYPE:
        raise ValueError(f"unknown SSO finding subtype: {record.subtype}")

    attributes["schema_version"] = SCHEMA_VERSION
    attributes["producer"] = record.producer
    attributes.setdefault("engine", record.producer)
    attributes.setdefault("sso_category", infer_sso_category(record.subtype))

    artifact = record.provenance.get("artifact", {})
    if not isinstance(artifact, dict):
        artifact = {}
    span = record.provenance.get("span", {})
    if not isinstance(span, dict):
        span = {}
    provenance = {
        **record.provenance,
        "producer": record.producer,
        "artifact": {
            **artifact,
            "id": record.artifact_id,
            "path": record.artifact_path,
        },
        "span": {
            **span,
            "start_line": record.span.start_line,
            "end_line": record.span.end_line,
        },
    }

    return SSOFinding(
        finding_id=record.finding_id,
        producer=record.producer,
        artifact_id=record.artifact_id,
        artifact_path=record.artifact_path,
        category=canonical_sso_category(record.subtype, record.category),
        subtype=record.subtype,
        matched_text=record.matched_text.strip(),
        confidence=(
            min(max(float(record.confidence), 0.0), 1.0)
            if record.confidence is not None
            else None
        ),
        span=record.span,
        attributes=attributes,
        provenance=provenance,
    )
