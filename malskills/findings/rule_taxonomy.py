from __future__ import annotations

from typing import Any


LEGACY_CATEGORY_DEFAULTS = {
    "Command Execution": ("payload_execution", "system_command_execution"),
    "Dynamic Execution": ("payload_execution", "dynamic_code_execution"),
    "Insecure Deserialization": ("payload_execution", "unsafe_deserialization"),
    "Network Access": ("network_access", "connection_create"),
    "File or System Operation": ("file_operation", "file_access"),
    "Sensitive Data": ("sensitive_data_access", "credential_data_access"),
    "Cryptography": ("cryptography", "cryptographic_operation"),
    "Obfuscation": ("cryptography", "encoding"),
}

LEGACY_SUBTYPE_OPERATIONS = {
    "direct_process_execution": ("payload_execution", "system_command_execution"),
    "shell_interpreter_execution": ("payload_execution", "system_command_execution"),
    "script_host_execution": ("payload_execution", "dynamic_code_execution"),
    "dynamic_module_load": ("payload_execution", "dynamic_code_execution"),
    "proxy_execution_or_lolbin_abuse": ("payload_execution", "system_command_execution"),
    "process_attach": ("process_operation", "process_memory_access"),
    "cross_process_memory_read": ("process_operation", "process_memory_access"),
    "cross_process_memory_write": ("process_operation", "process_memory_access"),
    "remote_thread_or_async_execution": ("process_operation", "process_control"),
    "executable_memory_mapping": ("process_operation", "process_memory_access"),
    "process_hollowing_or_image_replacement": ("process_operation", "process_memory_access"),
    "startup_or_logon_persistence": ("system_configuration", "system_configuration_modify"),
    "service_or_daemon_persistence": ("system_configuration", "system_configuration_modify"),
    "scheduled_persistence": ("system_configuration", "system_configuration_modify"),
    "event_triggered_persistence": ("system_configuration", "system_configuration_modify"),
    "boot_chain_persistence": ("system_configuration", "system_configuration_modify"),
    "identity_switch": ("process_operation", "process_control"),
    "privilege_adjustment": ("system_configuration", "system_configuration_modify"),
    "token_or_session_impersonation": ("process_operation", "process_control"),
    "group_or_acl_modification": ("file_operation", "file_permission_modify"),
    "boundary_bypass": ("system_configuration", "system_configuration_modify"),
    "password_or_hash_access": ("sensitive_data_access", "credential_data_access"),
    "session_or_token_access": ("sensitive_data_access", "credential_data_access"),
    "private_key_or_api_key_access": ("sensitive_data_access", "credential_data_access"),
    "credential_decryption": ("cryptography", "decryption"),
    "authentication_input_capture": ("sensitive_data_access", "credential_data_access"),
    "system_and_hardware_discovery": ("sensitive_data_access", "system_information_access"),
    "identity_and_account_discovery": ("sensitive_data_access", "user_information_access"),
    "process_and_service_discovery": ("sensitive_data_access", "process_information_access"),
    "network_and_neighbor_discovery": ("network_access", "network_configuration"),
    "domain_or_org_discovery": ("network_access", "dns_resolution"),
    "security_environment_discovery": ("sensitive_data_access", "system_information_access"),
    "file_enumeration_and_location": ("file_operation", "file_search"),
    "content_read_and_parse": ("file_operation", "file_read"),
    "bulk_copy_and_archive": ("file_operation", "file_write"),
    "config_or_metadata_modification": ("file_operation", "file_write"),
    "deletion_or_overwrite": ("file_operation", "file_delete"),
    "outbound_connection": ("network_access", "connection_create"),
    "listener_and_receive": ("network_access", "server_listen"),
    "tunneling_and_forwarding": ("network_access", "network_configuration"),
    "proxy_or_route_manipulation": ("network_access", "network_configuration"),
    "protocol_encapsulation_or_encrypted_comm": ("network_access", "connection_create"),
    "traffic_capture_and_observation": ("network_access", "data_receive"),
    "remote_login": ("network_access", "connection_create"),
    "remote_command_execution": ("payload_execution", "system_command_execution"),
    "remote_file_transfer": ("network_access", "data_send"),
    "remote_management_abuse": ("network_access", "connection_create"),
    "cluster_or_cloud_node_control": ("network_access", "connection_create"),
    "security_tool_impairment": ("process_operation", "process_control"),
    "logging_or_audit_suppression": ("system_configuration", "system_configuration_modify"),
    "policy_or_access_control_weakening": ("system_configuration", "system_configuration_modify"),
    "artifact_cleanup_or_timestomp": ("file_operation", "file_delete"),
    "object_hiding_or_visibility_evasion": ("file_operation", "file_write"),
    "data_destruction": ("file_operation", "file_delete"),
    "data_encryption_or_locking": ("cryptography", "encryption"),
    "recovery_impairment": ("system_configuration", "system_configuration_modify"),
    "availability_disruption": ("process_operation", "process_control"),
    "boot_or_low_level_destruction": ("system_configuration", "system_configuration_modify"),
}


def normalized_rule_operation(metadata: dict[str, Any]) -> tuple[str, str] | None:
    """Map an offline Semgrep rule to one neutral sensitive operation."""
    category = str(metadata.get("category", "")).strip()
    api = str(metadata.get("api", "")).strip().lower()
    if category not in LEGACY_CATEGORY_DEFAULTS:
        return None
    if category == "Network Access":
        return _network_operation(api)
    if category == "File or System Operation":
        return _file_or_system_operation(api)
    if category == "Sensitive Data":
        return _sensitive_data_operation(api)
    if category in {"Cryptography", "Obfuscation"}:
        return _crypto_operation(api, obfuscation=category == "Obfuscation")
    return LEGACY_CATEGORY_DEFAULTS[category]


def normalized_legacy_subtype(subtype: str) -> tuple[str, str] | None:
    return LEGACY_SUBTYPE_OPERATIONS.get(subtype)


def legacy_resource_class(subtype: str) -> str | None:
    if subtype in {
        "startup_or_logon_persistence",
        "service_or_daemon_persistence",
        "scheduled_persistence",
        "event_triggered_persistence",
        "boot_chain_persistence",
    }:
        return "startup_configuration"
    if subtype in {
        "identity_switch",
        "privilege_adjustment",
        "token_or_session_impersonation",
        "group_or_acl_modification",
        "boundary_bypass",
    }:
        return "privilege_boundary"
    if subtype == "recovery_impairment":
        return "recovery_configuration"
    return None


def legacy_operation_class(subtype: str) -> str | None:
    if subtype in {"data_destruction", "boot_or_low_level_destruction"}:
        return "destructive_rewrite"
    return None


def _network_operation(api: str) -> tuple[str, str]:
    if _has(api, "dns", "resolve", "resolver", "getaddrinfo", "gethostby", "hostbyname"):
        return "network_access", "dns_resolution"
    if _has(api, "listen", "accept", "bind", "createserver", "server(", "listener"):
        return "network_access", "server_listen"
    if _has(api, "send", "write", "post", "put", "upload", "outgoing", "publish"):
        return "network_access", "data_send"
    if _has(api, "recv", "receive", "read", "get(", "download", "incoming", "response"):
        return "network_access", "data_receive"
    if _has(api, "route", "proxy", "setsockopt", "setdefaulttimeout"):
        return "network_access", "network_configuration"
    return "network_access", "connection_create"


def _file_or_system_operation(api: str) -> tuple[str, str]:
    if _has(api, "getenv", "environ", "environment", "dotenv"):
        return "sensitive_data_access", "environment_access"
    if _has(api, "getpid", "getppid", "findprocess", "processes", "processid"):
        return "sensitive_data_access", "process_information_access"
    if _has(api, "getuid", "geteuid", "getgid", "getegid", "getuser", "current_user", "username"):
        return "sensitive_data_access", "user_information_access"
    if _has(api, "uname", "hostname", "platform", "sysinfo", "cpu_count", "machine"):
        return "sensitive_data_access", "system_information_access"
    if _has(api, "chmod", "chown", "permission", "setfacl", "acl"):
        return "file_operation", "file_permission_modify"
    if _has(api, "symlink", "hardlink", "readlink", "link("):
        return "file_operation", "link_operation"
    if _has(api, "walk", "scandir", "listdir", "readdir", "glob", "findfiles", "findfirstfile"):
        return "file_operation", "file_search"
    if _has(api, "unlink", "remove", "delete", "rmdir", "removedirs", "truncate"):
        return "file_operation", "file_delete"
    if _has(api, "mkdir", "makedirs", "create", "mkstemp", "tempfile", "touch"):
        return "file_operation", "file_create"
    if _has(api, "write", "append", "dump", "save", "copyfile", "rename", "replace"):
        return "file_operation", "file_write"
    if _has(api, "read", "load", "ifstream", "file_get_contents"):
        return "file_operation", "file_read"
    if _has(api, "kill", "terminate", "exit", "wait", "signal", "startprocess"):
        return "process_operation", "process_control"
    if _has(api, "registry", "regset", "setenv", "unsetenv", "chdir"):
        return "system_configuration", "system_configuration_modify"
    return "file_operation", "file_access"


def _sensitive_data_operation(api: str) -> tuple[str, str]:
    if _has(api, "getenv", "environ", "environment"):
        return "sensitive_data_access", "environment_access"
    if _has(api, "process", "pid"):
        return "sensitive_data_access", "process_information_access"
    if _has(api, "user", "uid", "gid"):
        return "sensitive_data_access", "user_information_access"
    if _has(api, "uname", "platform", "system", "machine", "version"):
        return "sensitive_data_access", "system_information_access"
    return "sensitive_data_access", "credential_data_access"


def _crypto_operation(api: str, *, obfuscation: bool) -> tuple[str, str]:
    if _has(api, "decode", "decompress", "unmarshal", "unhex", "fromhex"):
        return "cryptography", "decoding"
    if _has(api, "encode", "compress", "marshal", "base64", "hexlify", "tohex"):
        return "cryptography", "encoding"
    if _has(api, "decrypt", "decipher"):
        return "cryptography", "decryption"
    if _has(api, "encrypt", "cipher"):
        return "cryptography", "encryption"
    if _has(api, "hash", "sha", "md5", "digest", "hmac"):
        return "cryptography", "hashing"
    if _has(api, "key", "rsa", "aes", "ecdsa", "random"):
        return "cryptography", "cipher_object_creation"
    if obfuscation:
        return "cryptography", "encoding"
    return "cryptography", "cryptographic_operation"


def _has(value: str, *tokens: str) -> bool:
    return any(token in value for token in tokens)
