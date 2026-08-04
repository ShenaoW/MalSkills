from __future__ import annotations

__all__ = ["LlmObjectAnalyzer", "SDGCompiler", "YasaAdapter"]


def __getattr__(name: str):
    if name == "SDGCompiler":
        from .compiler import SDGCompiler

        return SDGCompiler
    if name == "LlmObjectAnalyzer":
        from .llm import LlmObjectAnalyzer

        return LlmObjectAnalyzer
    if name == "YasaAdapter":
        from .yasa import YasaAdapter

        return YasaAdapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
