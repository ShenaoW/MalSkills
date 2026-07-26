from __future__ import annotations

from .extractor import EvidenceExtractionResult, EvidenceExtractor
from .llm import LlmEvidenceExtractor
from .schema import REQUIRED_EVIDENCE_FIELDS, SCHEMA_VERSION, normalize_evidence_record

__all__ = [
    "EvidenceExtractionResult",
    "EvidenceExtractor",
    "LlmEvidenceExtractor",
    "REQUIRED_EVIDENCE_FIELDS",
    "SCHEMA_VERSION",
    "normalize_evidence_record",
]
