from __future__ import annotations

from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from malskills.evidence import EvidenceExtractor
from malskills.evaluation import VARIANTS
from malskills.ingest import SkillIngestor
from malskills.primitive import PrimitiveCompiler
from malskills.primitive.yasa import YasaAdapter


pytestmark = pytest.mark.skipif(not YasaAdapter().available(), reason="YASA runtime is unavailable")


def test_yasa_extracts_parameter_binding_from_real_js_sample() -> None:
    skill = Path("data/ground_truth/malicious/clawhub/rjnpage_rankaj")
    artifacts = SkillIngestor().ingest(skill)
    evidence = EvidenceExtractor().extract(skill, artifacts, enable_semgrep=True, enable_llm_evidence=False).evidence

    primitives, _, derived, combined = PrimitiveCompiler().synthesize(
        artifacts,
        evidence,
        skill_root=skill,
        enable_yasa=True,
        enable_cross_artifact_resolution=False,
    )

    assert primitives
    assert len(derived) == 1
    binding = derived[0]
    assert binding.evidence_type == "object_binding"
    assert binding.subtype == "parameter_binding"
    assert binding.value == "WEBHOOK_URL"
    assert binding.attributes.get("sink_api") == "fetch"
    assert binding.binding.get("parameter_role") == "endpoint"
    assert binding.binding.get("object_kind") == "symbolic_reference"
    assert len(combined) == len(evidence) + 1


def test_benchmark_full_variant_uses_current_pipeline() -> None:
    config = VARIANTS["benchmark_full"]
    assert config.enable_semgrep is True
    assert config.enable_llm_evidence is True
    assert config.enable_yasa is True
    assert config.enable_cross_artifact_resolution is True
    assert config.reasoning_mode == "hybrid"


def test_new_ablation_variants_are_registered() -> None:
    no_yasa = VARIANTS["benchmark_no_yasa"]
    assert no_yasa.enable_yasa is False
    assert no_yasa.enable_llm_evidence is True
    assert no_yasa.reasoning_mode == "hybrid"

    formal = VARIANTS["benchmark_formal_reasoning_only"]
    assert formal.reasoning_mode == "formal"
    assert formal.enable_llm_evidence is True
    assert formal.enable_semgrep is True

    llm_evidence = VARIANTS["benchmark_llm_evidence_only"]
    assert llm_evidence.enable_semgrep is False
    assert llm_evidence.enable_llm_evidence is True
    assert llm_evidence.reasoning_mode == "hybrid"

    static_only = VARIANTS["benchmark_static_only"]
    assert static_only.enable_llm_evidence is False
    assert static_only.enable_llm_object_analysis is False
    assert static_only.enable_yasa is False
    assert static_only.enable_cross_artifact_resolution is False
    assert static_only.reasoning_mode == "formal"


def test_codex_agent_baseline_variant_is_registered() -> None:
    assert VARIANTS["codex_agent_baseline"] == "codex_agent_baseline"
    assert VARIANTS["benchmark_codex_agent_baseline"] == "codex_agent_baseline"


def test_external_baseline_variants_are_registered() -> None:
    assert VARIANTS["skill_security_audit_baseline"] == "skill_security_audit_baseline"
    assert VARIANTS["benchmark_skill_security_audit_baseline"] == "skill_security_audit_baseline"
    assert VARIANTS["skill_security_scan_baseline"] == "skill_security_scan_baseline"
    assert VARIANTS["benchmark_skill_security_scan_baseline"] == "skill_security_scan_baseline"
    assert VARIANTS["skills_security_audit_baseline"] == "skills_security_audit_baseline"
    assert VARIANTS["benchmark_skills_security_audit_baseline"] == "skills_security_audit_baseline"
    assert VARIANTS["caterpillar_baseline"] == "caterpillar_baseline"
    assert VARIANTS["benchmark_caterpillar_baseline"] == "caterpillar_baseline"
    assert VARIANTS["clawscan_baseline"] == "clawscan_baseline"
    assert VARIANTS["benchmark_clawscan_baseline"] == "clawscan_baseline"
    assert VARIANTS["skill_scanner_baseline"] == "skill_scanner_baseline"
    assert VARIANTS["benchmark_skill_scanner_baseline"] == "skill_scanner_baseline"
    assert VARIANTS["nova_proximity_baseline"] == "nova_proximity_baseline"
    assert VARIANTS["benchmark_nova_proximity_baseline"] == "nova_proximity_baseline"
