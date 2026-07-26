from __future__ import annotations

from malskills.primitive import PrimitiveCompiler


def test_disabling_llm_object_analysis_skips_the_llm_analyzer(monkeypatch) -> None:
    compiler = PrimitiveCompiler()

    def unexpected_extract(*args, **kwargs):
        raise AssertionError("LLM object analysis should be disabled")

    monkeypatch.setattr(compiler.llm_analyzer, "extract", unexpected_extract)

    primitives, graph, derived, combined = compiler.synthesize(
        [],
        [],
        enable_llm_object_analysis=False,
        enable_yasa=False,
        enable_cross_artifact_resolution=False,
    )

    assert primitives == []
    assert derived == []
    assert combined == []
    assert graph["nodes"] == []
    assert graph["edges"] == []
