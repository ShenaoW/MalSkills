from __future__ import annotations

__all__ = ["LlmObjectAnalyzer", "PrimitiveCompiler", "YasaAdapter"]


def __getattr__(name: str):
    if name == "PrimitiveCompiler":
        from .compiler import PrimitiveCompiler

        return PrimitiveCompiler
    if name == "LlmObjectAnalyzer":
        from .llm import LlmObjectAnalyzer

        return LlmObjectAnalyzer
    if name == "YasaAdapter":
        from .yasa import YasaAdapter

        return YasaAdapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
