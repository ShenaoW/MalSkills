from __future__ import annotations

from ..models import PatternMatch, SkillVerdict


HIGH_SEVERITY = {
    "Data_Exfiltration",
    "Credential_Theft",
    "Remote_Code_Execution",
    "Malware_Delivery",
    "Persistence",
    "Reverse_Shell",
    "Ransomware",
    "Resource_Abuse",
    "Privilege_Escalation",
}
MEDIUM_SEVERITY = set()


class PatternVerdictBuilder:
    def dedupe_patterns(self, patterns: list[PatternMatch]) -> list[PatternMatch]:
        seen_names: set[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = set()
        deduped: list[PatternMatch] = []
        for pattern in patterns:
            key = (
                pattern.name,
                pattern.source,
                tuple(sorted(pattern.sso_ids)),
                tuple(sorted(pattern.finding_ids)),
            )
            if key in seen_names:
                continue
            seen_names.add(key)
            deduped.append(pattern)
        return deduped

    def patterns_to_verdict(self, skill_path: str, patterns: list[PatternMatch]) -> SkillVerdict:
        high_patterns_by_source: dict[str, set[str]] = {}
        medium_patterns_by_source: dict[str, set[str]] = {}
        for pattern in patterns:
            if pattern.name in HIGH_SEVERITY or pattern.severity == "high":
                high_patterns_by_source.setdefault(pattern.source, set()).add(pattern.name)
            elif pattern.name in MEDIUM_SEVERITY or pattern.severity == "medium":
                medium_patterns_by_source.setdefault(pattern.source, set()).add(pattern.name)

        all_high_patterns = sorted({name for names in high_patterns_by_source.values() for name in names})
        all_medium_patterns = sorted({name for names in medium_patterns_by_source.values() for name in names})
        malicious_patterns = all_high_patterns or all_medium_patterns
        if malicious_patterns:
            label = "malicious"
        else:
            label = "benign"
        decision_chain = [
            {
                "stage": "reasoning_sources",
                "sources": sorted({pattern.source for pattern in patterns}),
                "patterns_by_source": {
                    source: [pattern.name for pattern in patterns if pattern.source == source]
                    for source in sorted({pattern.source for pattern in patterns})
                },
            },
            {
                "stage": "pattern",
                "pattern_names": [pattern.name for pattern in patterns],
                "malicious_patterns": malicious_patterns,
            },
            {
                "stage": "verdict",
                "label": label,
            },
        ]
        verdict = SkillVerdict(
            skill_path=skill_path,
            label=label,
            malicious_patterns=malicious_patterns,
            summary=self.summarize(label, malicious_patterns),
        )
        setattr(verdict, "decision_chain", decision_chain)
        for pattern in patterns:
            explanation_chain = getattr(pattern, "explanation_chain", [])
            base_chain = (
                [step for step in explanation_chain if step.get("stage") != "verdict"]
                if explanation_chain
                else [
                {"stage": "sso_finding", "finding_ids": pattern.finding_ids},
                {"stage": "sso", "sso_ids": pattern.sso_ids},
                {"stage": "rule", "rule_ids": pattern.rule_ids},
                {"stage": "reasoning_source", "source": pattern.source},
                {
                    "stage": "pattern",
                    "pattern_id": pattern.pattern_id,
                    "pattern_name": pattern.name,
                    "severity": pattern.severity,
                },
            ]
            )
            setattr(pattern, "explanation_chain", [
                *base_chain,
                {
                    "stage": "verdict",
                    "label": verdict.label,
                },
            ])
        return verdict

    def summarize(
        self,
        label: str,
        malicious_patterns: list[str],
    ) -> str:
        if label == "malicious":
            return f"Detected malicious behavior patterns: {', '.join(malicious_patterns)}."
        return "No malicious capability composition was inferred from the current SSO set."
