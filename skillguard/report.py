from __future__ import annotations

import json
from pathlib import Path

from .models import AnalysisResult, to_jsonable
from .utils import ensure_dir


class ResultWriter:
    def write(self, result: AnalysisResult, output_dir: str | Path) -> None:
        destination = Path(output_dir)
        ensure_dir(destination)
        self._write_json(destination / "verdict.json", result.verdict)
        self._write_json(destination / "artifacts.json", result.artifacts)
        self._write_json(destination / "evidence.json", result.evidence)
        self._write_json(destination / "evidence_graph.json", result.graph)
        self._write_json(destination / "primitives.json", result.primitives)
        self._write_json(destination / "proofs.json", result.patterns)
        self._write_json(destination / "pattern_summary.json", self._summarize_patterns(result))
        self._write_markdown(destination / "human_report.md", result)

    def _write_json(self, path: Path, payload: object) -> None:
        path.write_text(json.dumps(to_jsonable(payload), indent=2, sort_keys=True), encoding="utf-8")

    def _summarize_patterns(self, result: AnalysisResult) -> list[dict[str, object]]:
        grouped: dict[str, list[object]] = {}
        for pattern in result.patterns:
            grouped.setdefault(pattern.name, []).append(pattern)
        summaries: list[dict[str, object]] = []
        for name, matches in sorted(grouped.items()):
            first = matches[0]
            primitive_ids = sorted({primitive_id for match in matches for primitive_id in match.primitive_ids})
            evidence_ids = sorted({evidence_id for match in matches for evidence_id in match.evidence_ids})
            summaries.append(
                {
                    "name": name,
                    "severity": first.severity,
                    "match_count": len(matches),
                    "rule_ids": first.rule_ids,
                    "primitive_ids": primitive_ids,
                    "evidence_ids": evidence_ids,
                    "explanation": first.explanation,
                }
            )
        return summaries

    def _write_markdown(self, path: Path, result: AnalysisResult) -> None:
        pattern_summaries = self._summarize_patterns(result)
        lines = [
            f"# Analysis Report: {result.skill_path}",
            "",
            f"- Verdict: `{result.verdict.label}`",
            f"- Score: `{result.verdict.score:.2f}`",
            f"- Malicious patterns: {', '.join(result.verdict.malicious_patterns) or 'none'}",
            f"- Suspicious patterns: {', '.join(result.verdict.suspicious_patterns) or 'none'}",
            "",
            "## Artifact Inventory",
            "",
            f"- Artifacts: {len(result.artifacts)}",
            f"- Evidence records: {len(result.evidence)}",
            f"- Primitive records: {len(result.primitives)}",
            "",
            "## Triggered Patterns",
        ]
        if not result.patterns:
            lines.append("- None")
        for summary in pattern_summaries:
            lines.append(f"- `{summary['name']}` ({summary['severity']}, matches={summary['match_count']}): {summary['explanation']}")
            lines.append(f"  - Rules: {', '.join(summary['rule_ids'])}")
            lines.append(f"  - Primitive IDs: {', '.join(summary['primitive_ids'][:5])}")
        lines.extend(["", "## Primitive Counts", ""])
        counts: dict[str, int] = {}
        for primitive in result.primitives:
            counts[primitive.primitive_type] = counts.get(primitive.primitive_type, 0) + 1
        if not counts:
            lines.append("- None")
        else:
            for name, count in sorted(counts.items()):
                lines.append(f"- `{name}`: {count}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
