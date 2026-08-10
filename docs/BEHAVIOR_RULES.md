# SDG Behavior Rules

Behavior reasoning uses nine malicious behavior classes. These are not SSO
types and are not ATT&CK tactic labels. An SSO records one behavior-neutral
sensitive operation; a behavior rule requires a connected SDG subgraph.

| Behavior | Required graph query |
|---|---|
| `Data_Exfiltration` | sensitive/host access `--value_flow-->` external `data_send` |
| `Credential_Theft` | `credential_data_access --value_flow-->` external `data_send` |
| `Remote_Code_Execution` | `data_receive --value_flow--> execution` |
| `Malware_Delivery` | `data_receive --value_flow--> file_write --value_flow_or_same_object--> execution` |
| `Persistence` | execution `--value_flow_or_same_object-->` startup configuration modification |
| `Reverse_Shell` | `data_receive --value_flow--> execution --value_flow--> data_send` |
| `Ransomware` | `file_read --value_flow--> encryption --value_flow_or_same_object-->` destructive rewrite/delete |
| `Resource_Abuse` | `data_receive --value_flow-->` resource-intensive compute `--value_flow--> data_send` |
| `Privilege_Escalation` | execution `--value_flow_or_same_object-->` privilege-boundary modification |

For in-memory or directly downloaded payloads, `Malware_Delivery` also accepts
`data_receive --value_flow_or_same_object--> execution`. The shared-object branch
requires an explicitly resolved payload identity; line proximity is not a relation.

The built-in query specifications are in `malskills/rules/workflows/builtin/`.
`value_flow` is directional and follows at most eight SDG edges. Reversed flow
does not match. `same_object` is symmetric and is used only when two operations
act on the same staged payload or configuration resource.

Roles may constrain structural SSO attributes. In particular,
`resource_class=startup_configuration` distinguishes persistence targets from
other system configuration, and `resource_class=privilege_boundary`
distinguishes authorization changes from ordinary permission operations. These
attributes are assigned by SSO extraction rules; the behavior reasoner does not
inspect command text, paths, API names, or package names.

Likewise, ransomware requires `operation_class=destructive_rewrite`, and
resource abuse requires `operation_class=resource_intensive_computation`.
Ordinary file encryption and ordinary hashing therefore do not satisfy either
query merely because their API sequence looks similar.

YASA proof paths are materialized as directed `sso_taint` value-flow edges when
a source SSO location occurs before a sink in the same proof. Syntax-only SSOs
can still participate through explicit object identity, but same-file
co-occurrence is never considered a dependency.

Shell and shell-in-Markdown flows use a deterministic syntax frontend. It adds
`shell_pipeline` value-flow edges only for an explicit pipe or command
substitution in one logical statement. Generated fenced-code locations are
mapped back to their source Markdown lines. Ordinary same-line, nearby-line, or
same-file operations are not connected, and ambiguous statements containing
multiple independent data-flow clauses are left unresolved.

Markdown also emits `markdown_explicit_flow` for the constrained construction
"download ... and/then run it/the executable". This is treated as an explicit
coreference relation; other same-line or nearby prose remains disconnected.

Archive extraction remains a neutral `decoding` SSO with
`operation_class=archive_extraction`. When extraction has explicit `input` and
`output` operands, the compiler emits `object_transform` edges from a producer
of the exact input object through the decoding SSO to a consumer of the exact
output object. Filename similarity and line proximity never create these edges.
