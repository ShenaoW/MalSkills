# Neutral SSO Taxonomy

An SSO describes one source-grounded security-sensitive operation. It does not
describe attacker intent or a malicious behavior pattern. Persistence, command
and control, lateral movement, defense evasion, information theft, and
ransomware are reasoning results over connected SSOs in the SDG, not SSO types.

| Category | Subtypes |
| --- | --- |
| `payload_execution` | `system_command_execution`, `dynamic_code_execution`, `external_file_execution`, `unsafe_deserialization` |
| `network_access` | `connection_create`, `server_listen`, `dns_resolution`, `data_send`, `data_receive`, `network_configuration` |
| `file_operation` | `file_access`, `file_create`, `file_delete`, `file_read`, `file_write`, `file_permission_modify`, `link_operation`, `file_search` |
| `sensitive_data_access` | `system_information_access`, `environment_access`, `process_information_access`, `user_information_access`, `credential_data_access` |
| `cryptography` | `cipher_object_creation`, `encryption`, `decryption`, `hashing`, `encoding`, `decoding`, `cryptographic_operation` |
| `software_installation` | `package_installation`, `external_component_installation` |
| `process_operation` | `process_control`, `process_memory_access` |
| `system_configuration` | `system_configuration_modify` |

Directional subtypes are used only when syntax or API semantics establish the
direction. For example, `send`, `post`, and `write` network APIs produce
`data_send`; `recv`, response-read, and download APIs produce `data_receive`.
Ambiguous APIs produce `connection_create`. Likewise, an unqualified `open`
produces `file_access` unless its mode or API establishes read, write, create,
or delete semantics.

The default code rule corpus contains 2,665 Semgrep rules over C, C++, C#, Go,
Java, JavaScript, PHP, Python, Ruby, and TypeScript. The checked-in legacy corpus
contributes 2,664 rules; `getpass.getuser()` supplies the missing neutral
user-information rule. Markdown and Shell artifact rules are loaded separately
and are not included in the 2,665 code-rule count.
