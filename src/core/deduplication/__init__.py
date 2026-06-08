"""Deduplication package"""
from src.core.deduplication.finding_deduplicator import (
    FindingDeduplicator,
    deduplicate_findings,
)

__all__ = [
    "FindingDeduplicator",
    "deduplicate_findings",
]
