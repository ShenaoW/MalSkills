from __future__ import annotations

from typing import Any

from ..models import SSOFinding

SCHEMA_VERSION = "sso-finding-v3"
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
    "system_command_execution": "payload_execution",
    "dynamic_code_execution": "payload_execution",
    "external_file_execution": "payload_execution",
    "unsafe_deserialization": "payload_execution",
    "connection_create": "network_access",
    "server_listen": "network_access",
    "dns_resolution": "network_access",
    "data_send": "network_access",
    "data_receive": "network_access",
    "network_configuration": "network_access",
    "file_access": "file_operation",
    "file_create": "file_operation",
    "file_delete": "file_operation",
    "file_read": "file_operation",
    "file_write": "file_operation",
    "file_permission_modify": "file_operation",
    "link_operation": "file_operation",
    "file_search": "file_operation",
    "system_information_access": "sensitive_data_access",
    "environment_access": "sensitive_data_access",
    "process_information_access": "sensitive_data_access",
    "user_information_access": "sensitive_data_access",
    "credential_data_access": "sensitive_data_access",
    "cipher_object_creation": "cryptography",
    "encryption": "cryptography",
    "decryption": "cryptography",
    "hashing": "cryptography",
    "encoding": "cryptography",
    "decoding": "cryptography",
    "cryptographic_operation": "cryptography",
    "package_installation": "software_installation",
    "external_component_installation": "software_installation",
    "process_control": "process_operation",
    "process_memory_access": "process_operation",
    "system_configuration_modify": "system_configuration",
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
