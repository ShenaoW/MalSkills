from __future__ import annotations

import hashlib
import itertools
import json
import re
from collections import deque
from pathlib import Path
from typing import Any

from ..models import PatternMatch, SSORecord, WorkflowDiscovery

WORKFLOW_SCHEMA_VERSION = "malskills-workflow-rule-v1"
ALLOWED_RELATIONS = {"same_object", "value_flow"}
MAX_WORKFLOW_MATCH_STATES = 100_000
ALLOWED_PATTERN_NAMES = {
    "Execution_and_Delivery",
    "Persistence",
    "Privilege_Escalation_and_Identity_Abuse",
    "Injection_and_Covert_Residency",
    "Information_Theft",
    "Command_and_Control",
    "Lateral_Movement",
    "Defense_Evasion_and_Anti_Forensics",
    "Destruction_and_Ransomware",
}


class WorkflowRuleError(ValueError):
    pass


def build_workflow_spec(
    discovery: WorkflowDiscovery,
    ssos: list[SSORecord],
    graph: dict[str, Any],
) -> dict[str, Any] | None:
    sso_by_id = {item.sso_id: item for item in ssos}
    support = [sso_by_id[item] for item in discovery.sso_ids if item in sso_by_id]
    support = sorted(support, key=lambda item: (item.subtype, item.artifact_paths, item.sso_id))
    if len(support) < 2 or len(support) > 6:
        return None
    if len({_sso_callsite_key(item) for item in support}) < 2:
        return None

    roles = [
        {
            "id": f"p{index}",
            "subtypes": [sso.subtype],
            "min_confidence": 0.0,
        }
        for index, sso in enumerate(support)
    ]
    relation_rows: list[dict[str, str]] = []
    connected_pairs: list[tuple[int, int]] = []
    graph_index = _GraphIndex(graph)
    for left_index, left in enumerate(support):
        for right_index in range(left_index + 1, len(support)):
            right = support[right_index]
            if graph_index.share_object(left, right):
                relation_rows.append(
                    {"kind": "same_object", "left": f"p{left_index}", "right": f"p{right_index}"}
                )
                connected_pairs.append((left_index, right_index))
                continue
            if graph_index.has_value_flow(left, right):
                relation_rows.append(
                    {"kind": "value_flow", "left": f"p{left_index}", "right": f"p{right_index}"}
                )
                connected_pairs.append((left_index, right_index))
            elif graph_index.has_value_flow(right, left):
                relation_rows.append(
                    {"kind": "value_flow", "left": f"p{right_index}", "right": f"p{left_index}"}
                )
                connected_pairs.append((left_index, right_index))

    if not _is_connected(len(support), connected_pairs):
        return None

    workflow_name = _slug(discovery.workflow_name) or _slug(discovery.pattern_name)
    canonical = {
        "pattern_name": discovery.pattern_name,
        "workflow_name": workflow_name,
        "roles": roles,
        "relations": sorted(relation_rows, key=lambda item: (item["kind"], item["left"], item["right"])),
    }
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": WORKFLOW_SCHEMA_VERSION,
        "rule_id": f"learned.workflow.{workflow_name}.{digest[:12]}",
        "pattern_name": discovery.pattern_name,
        "workflow_name": workflow_name,
        "severity": "high",
        "decision_effect": "suspicious",
        "roles": roles,
        "relations": canonical["relations"],
        "explanation": discovery.explanation,
        "semantic_fingerprint": digest,
    }


def _sso_callsite_key(sso: SSORecord) -> tuple[str, object]:
    callsite = str(sso.attributes.get("sink_callsite_id", "")).strip()
    parts = callsite.rsplit(":", 3)
    if len(parts) == 4:
        try:
            return parts[0], int(parts[1])
        except ValueError:
            pass
    return "sso", sso.sso_id


class WorkflowRuleMatcher:
    def load_rules(self, rules_dir: str | Path | None) -> list[dict[str, Any]]:
        if rules_dir is None:
            return []
        root = Path(rules_dir)
        if not root.exists():
            return []
        rules: list[dict[str, Any]] = []
        for path in sorted(root.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise WorkflowRuleError(f"invalid workflow rule file {path}: {exc}") from exc
            self.validate_rule(payload)
            rules.append(payload)
        return rules

    def validate_rule(self, rule: object) -> None:
        if not isinstance(rule, dict):
            raise WorkflowRuleError("workflow rule must be an object")
        if rule.get("schema_version") != WORKFLOW_SCHEMA_VERSION:
            raise WorkflowRuleError("unsupported workflow rule schema")
        for key in ("rule_id", "pattern_name", "workflow_name", "severity", "roles", "relations"):
            if key not in rule:
                raise WorkflowRuleError(f"workflow rule is missing {key}")
        if str(rule.get("pattern_name", "")) not in ALLOWED_PATTERN_NAMES:
            raise WorkflowRuleError("workflow rule uses an unsupported pattern name")
        if not re.fullmatch(r"[a-z0-9_]{1,80}", str(rule.get("workflow_name", ""))):
            raise WorkflowRuleError("workflow_name must be stable snake_case")
        if str(rule.get("severity", "")) != "high":
            raise WorkflowRuleError("workflow rule severity must match the reasoning taxonomy")
        if rule.get("decision_effect", "suspicious") != "suspicious":
            raise WorkflowRuleError("learned workflow rules may only have a suspicious decision effect")
        roles = rule.get("roles")
        relations = rule.get("relations")
        if not isinstance(roles, list) or not 2 <= len(roles) <= 6:
            raise WorkflowRuleError("workflow rule must contain two to six roles")
        if not isinstance(relations, list) or not relations:
            raise WorkflowRuleError("workflow rule must contain dependency relations")
        role_ids: set[str] = set()
        for role in roles:
            if not isinstance(role, dict):
                raise WorkflowRuleError("workflow role must be an object")
            role_id = str(role.get("id", "")).strip()
            subtypes = role.get("subtypes")
            if not role_id or role_id in role_ids:
                raise WorkflowRuleError("workflow role ids must be non-empty and unique")
            if not isinstance(subtypes, list) or not subtypes or not all(
                isinstance(item, str) and item for item in subtypes
            ):
                raise WorkflowRuleError("workflow role subtypes must be a non-empty string list")
            try:
                minimum = float(role.get("min_confidence", 0.0))
            except (TypeError, ValueError) as exc:
                raise WorkflowRuleError("workflow role min_confidence must be numeric") from exc
            if not 0.0 <= minimum <= 1.0:
                raise WorkflowRuleError("workflow role min_confidence must be between zero and one")
            role_ids.add(role_id)
        pairs: list[tuple[int, int]] = []
        role_order = {role_id: index for index, role_id in enumerate(sorted(role_ids))}
        for relation in relations:
            if not isinstance(relation, dict):
                raise WorkflowRuleError("workflow relation must be an object")
            kind = str(relation.get("kind", ""))
            left = str(relation.get("left", ""))
            right = str(relation.get("right", ""))
            if kind not in ALLOWED_RELATIONS:
                raise WorkflowRuleError(f"unsupported workflow relation: {kind}")
            if left not in role_ids or right not in role_ids or left == right:
                raise WorkflowRuleError("workflow relation references an invalid role")
            pairs.append((role_order[left], role_order[right]))
        if not _is_connected(len(role_ids), pairs):
            raise WorkflowRuleError("workflow rule roles must form a connected dependency graph")

    def match(
        self,
        ssos: list[SSORecord],
        graph: dict[str, Any],
        rules: list[dict[str, Any]],
    ) -> list[PatternMatch]:
        graph_index = _GraphIndex(graph)
        matches: list[PatternMatch] = []
        counter = 0
        for rule in rules:
            self.validate_rule(rule)
            roles = list(rule["roles"])
            candidate_sets: dict[str, list[SSORecord]] = {}
            for role in roles:
                allowed = set(role["subtypes"])
                minimum = float(role.get("min_confidence", 0.0))
                candidate_sets[str(role["id"])] = sorted(
                    [
                        item
                        for item in ssos
                        if item.subtype in allowed
                        and (
                            (item.confidence is not None and item.confidence >= minimum)
                            or (item.confidence is None and minimum == 0.0)
                        )
                    ],
                    key=lambda item: item.sso_id,
                )
            if any(not values for values in candidate_sets.values()):
                continue
            binding = self._find_binding(
                roles,
                list(rule["relations"]),
                candidate_sets,
                graph_index,
            )
            if binding is None:
                continue
            assignment = [binding[str(role["id"])] for role in roles]
            sso_ids = [item.sso_id for item in assignment]
            finding_ids = _stable(
                [finding_id for sso in assignment for finding_id in sso.finding_ids]
            )
            matches.append(
                PatternMatch(
                    pattern_id=f"learned_pat_{counter:05d}",
                    name=str(rule["pattern_name"]),
                    severity=str(rule.get("severity", "high")),
                    rule_ids=[str(rule["rule_id"])],
                    sso_ids=_stable(sso_ids),
                    finding_ids=finding_ids,
                    explanation=str(
                        rule.get(
                            "explanation",
                            "Matched a validated reusable workflow rule.",
                        )
                    ),
                    source="learned",
                )
            )
            counter += 1
        return matches

    def _find_binding(
        self,
        roles: list[dict[str, Any]],
        relations: list[dict[str, str]],
        candidate_sets: dict[str, list[SSORecord]],
        graph: "_GraphIndex",
    ) -> dict[str, SSORecord] | None:
        role_ids = sorted(
            (str(role["id"]) for role in roles),
            key=lambda role_id: (len(candidate_sets[role_id]), role_id),
        )
        binding: dict[str, SSORecord] = {}
        used: set[str] = set()
        states = 0

        def search(index: int) -> dict[str, SSORecord] | None:
            nonlocal states
            if index == len(role_ids):
                return dict(binding)
            role_id = role_ids[index]
            for sso in candidate_sets[role_id]:
                states += 1
                if states > MAX_WORKFLOW_MATCH_STATES:
                    return None
                if sso.sso_id in used:
                    continue
                binding[role_id] = sso
                used.add(sso.sso_id)
                if self._partial_relations_hold(binding, relations, graph):
                    result = search(index + 1)
                    if result is not None:
                        return result
                used.remove(sso.sso_id)
                del binding[role_id]
            return None

        return search(0)

    def connected(
        self,
        left: SSORecord,
        right: SSORecord,
        graph: dict[str, Any],
    ) -> bool:
        graph_index = _GraphIndex(graph)
        return (
            graph_index.share_object(left, right)
            or graph_index.has_value_flow(left, right)
            or graph_index.has_value_flow(right, left)
        )

    def _relations_hold(
        self,
        binding: dict[str, SSORecord],
        relations: list[dict[str, str]],
        graph: "_GraphIndex",
    ) -> bool:
        for relation in relations:
            left = binding[relation["left"]]
            right = binding[relation["right"]]
            if relation["kind"] == "same_object" and not graph.share_object(left, right):
                return False
            if relation["kind"] == "value_flow" and not graph.has_value_flow(left, right):
                return False
        return True

    def _partial_relations_hold(
        self,
        binding: dict[str, SSORecord],
        relations: list[dict[str, str]],
        graph: "_GraphIndex",
    ) -> bool:
        ready = [
            relation
            for relation in relations
            if relation["left"] in binding and relation["right"] in binding
        ]
        return self._relations_hold(binding, ready, graph)


def canonicalize_workflow_structure(
    rule: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    WorkflowRuleMatcher().validate_rule(rule)
    roles = list(rule["roles"])
    relations = list(rule["relations"])
    best_key: str | None = None
    best_roles: list[dict[str, Any]] = []
    best_relations: list[dict[str, str]] = []
    for permutation in itertools.permutations(range(len(roles))):
        role_id_map = {
            str(roles[old_index]["id"]): f"p{new_index}"
            for new_index, old_index in enumerate(permutation)
        }
        normalized_roles = [
            {
                "id": f"p{new_index}",
                "subtypes": sorted(
                    set(str(item) for item in roles[old_index]["subtypes"])
                ),
                "min_confidence": float(roles[old_index].get("min_confidence", 0.0)),
            }
            for new_index, old_index in enumerate(permutation)
        ]
        normalized_relations: list[dict[str, str]] = []
        for relation in relations:
            kind = str(relation["kind"])
            left = role_id_map[str(relation["left"])]
            right = role_id_map[str(relation["right"])]
            if kind == "same_object" and right < left:
                left, right = right, left
            normalized_relations.append({"kind": kind, "left": left, "right": right})
        relation_tuples = sorted(
            {
                (item["kind"], item["left"], item["right"])
                for item in normalized_relations
            }
        )
        relation_payload = [
            {"kind": kind, "left": left, "right": right}
            for kind, left, right in relation_tuples
        ]
        key = json.dumps(
            {
                "roles": [
                    {
                        "subtypes": item["subtypes"],
                        "min_confidence": item["min_confidence"],
                    }
                    for item in normalized_roles
                ],
                "relations": relation_payload,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        if best_key is None or key < best_key:
            best_key = key
            best_roles = normalized_roles
            best_relations = relation_payload
    return best_roles, best_relations


class _GraphIndex:
    def __init__(self, graph: dict[str, Any]) -> None:
        self.edges = [edge for edge in graph.get("edges", []) if isinstance(edge, dict)]
        self.object_by_sso: dict[str, set[str]] = {}
        self.same_object_pairs: set[frozenset[str]] = set()
        self.value_flow: dict[str, set[str]] = {}
        self.bound_values: dict[str, set[str]] = {}
        for edge in self.edges:
            source = str(edge.get("source", ""))
            target = str(edge.get("target", ""))
            kind = str(edge.get("type", ""))
            if kind in {"acts_on", "associated_with", "has_operand"}:
                self.object_by_sso.setdefault(source, set()).add(target)
            elif kind == "same_object":
                self.same_object_pairs.add(frozenset((source, target)))
            elif kind == "value_flow":
                self.value_flow.setdefault(source, set()).add(target)
                if str(edge.get("flow_kind", "")) == "binding":
                    self.bound_values.setdefault(source, set()).add(target)

    def objects(self, sso: SSORecord) -> set[str]:
        values = set(self.object_by_sso.get(sso.sso_id, set()))
        operation_object = sso.attributes.get("operation_object")
        if operation_object:
            values.add(str(operation_object))
        related = sso.attributes.get("related_objects") or []
        if isinstance(related, list):
            values.update(str(item) for item in related if item)
        return values

    def share_object(self, left: SSORecord, right: SSORecord) -> bool:
        if frozenset((left.sso_id, right.sso_id)) in self.same_object_pairs:
            return True
        return bool(self.objects(left) & self.objects(right))

    def has_value_flow(self, left: SSORecord, right: SSORecord) -> bool:
        right_objects = self.objects(right)
        targets = set(right_objects)
        for object_id in right_objects:
            targets.update(self.bound_values.get(object_id, set()))
        if not targets:
            return False
        queue = deque((item, 0) for item in self.objects(left))
        seen = {item for item, _ in queue}
        while queue:
            current, depth = queue.popleft()
            if current in targets and depth > 0:
                return True
            if depth >= 8:
                continue
            for candidate in self.value_flow.get(current, set()):
                if candidate in seen:
                    continue
                seen.add(candidate)
                queue.append((candidate, depth + 1))
        return False


def _is_connected(size: int, pairs: list[tuple[int, int]]) -> bool:
    if size < 2:
        return False
    adjacency: dict[int, set[int]] = {index: set() for index in range(size)}
    for left, right in pairs:
        adjacency[left].add(right)
        adjacency[right].add(left)
    seen = {0}
    queue = deque([0])
    while queue:
        current = queue.popleft()
        for candidate in adjacency[current]:
            if candidate in seen:
                continue
            seen.add(candidate)
            queue.append(candidate)
    return len(seen) == size


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")[:80]


def _stable(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
