from __future__ import annotations

__all__ = ["AnalyzerConfig", "SkillAnalyzer"]


def __getattr__(name: str):
    if name in __all__:
        from .pipeline import AnalyzerConfig, SkillAnalyzer

        return {
            "AnalyzerConfig": AnalyzerConfig,
            "SkillAnalyzer": SkillAnalyzer,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
