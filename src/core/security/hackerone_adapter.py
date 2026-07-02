"""
HackerOne Provider Adapter.

Reads a HackerOne program bundle (policy.md + scope_assets.csv) and
produces provider-neutral NormalizedFacts.

Contract: docs/shigoku/specs/2026-07-01_sgk-2026-0335_bug-bounty-program-bundle-guard-policy-contract.md
Sections 6.2-6.2.6.
"""

from __future__ import annotations

import csv
import re
from io import StringIO
from pathlib import Path
from typing import Any, Optional, Union

from src.core.security.program_adapter_base import (
    NormalizedAsset,
    NormalizedFacts,
    ProgramAdapterBase,
    RuleCandidate,
    ReviewCandidate,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REQUIRED_CSV_COLUMNS = [
    "identifier",
    "asset_type",
    "instruction",
    "eligible_for_bounty",
    "eligible_for_submission",
    "availability_requirement",
    "confidentiality_requirement",
    "integrity_requirement",
    "max_severity",
]

# Policy text extraction patterns (regex, case-insensitive)
POLICY_PATTERNS: list[dict[str, Any]] = [
    # Social engineering prohibition
    {
        "pattern": re.compile(r"social\s*engineering", re.IGNORECASE),
        "category": "attack_class",
        "subject": "social_engineering",
        "decision": "deny",
        "specificity": "broad",
    },
    # DoS / service disruption prohibition
    {
        "pattern": re.compile(r"(?:dos|ddos|denial\s*of\s*service|service\s*disruption)", re.IGNORECASE),
        "category": "attack_class",
        "subject": "dos",
        "decision": "deny",
        "specificity": "broad",
    },
    # Privacy violations / privacy harm prohibition
    {
        "pattern": re.compile(r"privacy\s*violation", re.IGNORECASE),
        "category": "attack_class",
        "subject": "privacy_harm",
        "decision": "deny",
        "specificity": "broad",
    },
    # Post-exploit prohibition: "stop there and report immediately"
    {
        "pattern": re.compile(r"stop\s+there\s+and\s+report\s+immediately", re.IGNORECASE),
        "category": "phase",
        "subject": "post_exploit",
        "decision": "deny",
        "specificity": "medium",
    },
    # Post-exploit prohibition: "Do not move laterally"
    {
        "pattern": re.compile(r"do\s+not\s+move\s+laterally", re.IGNORECASE),
        "category": "phase",
        "subject": "post_exploit",
        "decision": "deny",
        "specificity": "medium",
    },
]

# SSRF-specific patterns
SSRF_SHERIFF_PATTERN = re.compile(
    r"(?:only|permitted)\s+(?:against|to)\s+(?:the\s+following|these)\s+destinations?",
    re.IGNORECASE,
)
SSRF_URL_PATTERN = re.compile(
    r"-\s*(?:`)?(https?://[^\s`]+)(?:`)?", re.IGNORECASE
)
SSRF_DENY_OTHER = re.compile(
    r"(?:do\s+not\s+test\s+ssrf|ssrf.*against\s+any\s+other)", re.IGNORECASE
)

# Mobile app detection values (may appear in asset_type or instruction)
MOBILE_APP_VALUES = {"GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID"}

# Category short names for review finding IDs
CATEGORY_SHORT = {
    "temporal_scope": "TMP",
    "scope_mismatch": "SCM",
    "ambiguity": "AMB",
    "timezone_parse": "TZ",
    "wildcard_deny_conflict": "WDC",
}


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class HackerOneAdapter(ProgramAdapterBase):
    """HackerOne provider adapter.

    Reads policy.md for text-based rules and scope_assets.csv for
    structured asset scope. Produces NormalizedFacts with provider-neutral
    assets, rule candidates, and review candidates.
    """

    ADAPTER_NAME = "hackerone_program_adapter"
    ADAPTER_VERSION = 1
    PROVIDER = "hackerone"

    def __init__(self, bundle_dir: Union[str, Path]):
        super().__init__(bundle_dir)
        self._csv_rows: list[dict[str, str]] = []

    # ---- Provider-specific fact extraction -----------------------------------

    def _extract_provider_facts(self, facts: NormalizedFacts) -> None:
        """Extract HackerOne-specific facts from policy.md and scope_assets.csv."""
        # Set program name from manifest
        facts.program["program_name"] = self._manifest.get("program_name", "")

        # 1. Parse CSV scope assets
        self._parse_scope_csv(facts)

        # 2. Extract rules from policy text
        self._extract_policy_text_rules(facts)

    # ---- CSV parsing ---------------------------------------------------------

    def _parse_scope_csv(self, facts: NormalizedFacts) -> None:
        """Parse scope_assets.csv and populate facts.assets."""
        # Find CSV source in scope_sources
        csv_source = None
        for src in self._manifest.get("scope_sources", []):
            if src.get("kind") == "hackerone_csv":
                csv_source = src
                break

        if csv_source is None:
            facts.add_audit("parse_csv", "failed",
                            "No hackerone_csv scope source found")
            raise ValueError(
                "scope_sources must include an entry with kind=hackerone_csv"
            )

        csv_path_key = csv_source.get("path", "")
        if not csv_path_key:
            raise ValueError("scope_sources entry is missing 'path'")

        if csv_path_key not in self._sources:
            facts.add_audit("parse_csv", "failed",
                            f"CSV source not loaded: {csv_path_key}")
            raise ValueError(
                f"Scope CSV '{csv_path_key}' not found in loaded sources"
            )

        raw_csv = self._sources[csv_path_key]
        reader = csv.DictReader(StringIO(raw_csv))

        # Validate required columns
        if reader.fieldnames is None:
            raise ValueError("scope_assets.csv has no header row")
        missing = set(REQUIRED_CSV_COLUMNS) - set(reader.fieldnames)
        if missing:
            facts.add_audit("parse_csv", "failed",
                            f"Missing required columns: {sorted(missing)}")
            raise ValueError(
                f"scope_assets.csv missing required columns: {sorted(missing)}"
            )

        row_index = 0
        for row in reader:
            row_index += 1
            identifier = row.get("identifier", "").strip()
            asset_type = row.get("asset_type", "").strip()
            instruction = row.get("instruction", "").strip()
            eligible_bounty = self._parse_bool(row.get("eligible_for_bounty", ""))
            eligible_submission = self._parse_bool(row.get("eligible_for_submission", ""))
            max_severity = row.get("max_severity", "none").strip().lower()

            if not identifier:
                facts.add_audit("parse_csv", "warning",
                                f"Row {row_index}: empty identifier, skipping",
                                [f"{csv_path_key}#row={row_index}"])
                continue

            # Determine asset kind
            asset_kind, runtime_surface = self._classify_asset(
                identifier, asset_type, instruction
            )

            asset = NormalizedAsset(
                asset_id=f"h1-asset-{row_index}",
                raw_identifier=identifier,
                canonical_key="",  # filled by normalize_assets
                asset_kind=asset_kind,
                runtime_surface=runtime_surface,
                submission_allowed=eligible_submission,
                bounty_allowed=eligible_bounty,
                max_severity=max_severity,
                provider_metadata={
                    "csv_row": row_index,
                    "asset_type_raw": asset_type,
                    "instruction": instruction,
                },
                source_ref=f"scope_assets.csv#row={row_index}",
            )
            facts.assets.append(asset)

        facts.add_audit("parse_csv", "ok",
                        f"Parsed {len(facts.assets)} assets from {csv_path_key}")

    def _classify_asset(
        self, identifier: str, asset_type: str, instruction: str
    ) -> tuple[str, str]:
        """Classify an asset into asset_kind and runtime_surface.

        Returns (asset_kind, runtime_surface) tuple.
        """
        # Check for mobile app indicators in asset_type OR instruction
        # (handles malformed CSVs where these values end up in instruction)
        combined = f"{asset_type} {instruction}".upper()
        for mobile_val in MOBILE_APP_VALUES:
            if mobile_val in combined:
                return ("mobile_app", "mobile")

        # Check for URL with scheme -> url_prefix
        if asset_type.upper() == "URL":
            if identifier.startswith(("https://", "http://")):
                return ("url_prefix", "http")
            else:
                return ("host_exact", "http")

        # Check for WILDCARD type or identifier containing *.
        if asset_type.upper() == "WILDCARD" or "*." in identifier or identifier.startswith("*"):
            return ("host_wildcard", "http")

        # Default
        return ("other", "http")

    @staticmethod
    def _parse_bool(value: str) -> bool:
        """Parse a boolean string from CSV."""
        v = value.strip().lower()
        return v in ("true", "yes", "1")

    # ---- Policy text rule extraction -----------------------------------------

    def _extract_policy_text_rules(self, facts: NormalizedFacts) -> None:
        """Extract behavioral rules from policy.md text."""
        text = self._raw_policy
        if not text:
            return

        rule_counter: dict[str, int] = {}

        # 1. Pattern-based extraction
        for pattern_def in POLICY_PATTERNS:
            if pattern_def["pattern"].search(text):
                category = pattern_def["category"]
                subject = pattern_def["subject"]
                decision = pattern_def["decision"]
                specificity = pattern_def["specificity"]

                # Deduplicate: only one rule per (category, subject)
                existing = [
                    rc for rc in facts.rule_candidates
                    if rc.category == category and rc.subject == subject
                ]
                if existing:
                    continue

                rule_counter[category] = rule_counter.get(category, 0) + 1
                rule_id = f"h1-rule-{category}-{rule_counter[category]}"

                facts.rule_candidates.append(RuleCandidate(
                    rule_id=rule_id,
                    category=category,
                    decision=decision,
                    subject=subject,
                    constraints={},
                    origin_type="policy_text",
                    specificity=specificity,
                    source_ref="policy.md",
                ))

        # 2. SSRF-specific extraction
        self._extract_ssrf_rules(text, facts, rule_counter)

        facts.add_audit("extract_policy_rules", "ok",
                        f"Extracted {len(facts.rule_candidates)} rule candidates from policy text")

    def _extract_ssrf_rules(
        self, text: str, facts: NormalizedFacts, rule_counter: dict[str, int]
    ) -> None:
        """Extract SSRF-specific allow/deny rules from policy text."""
        # Check if policy contains SSRF sheriff language
        sheriff_match = SSRF_SHERIFF_PATTERN.search(text)
        if not sheriff_match:
            return

        # Scope URL extraction to the text after the SSRF sheriff marker
        # (to avoid picking up URLs from other sections like exclusions)
        ssrf_section = text[sheriff_match.start():]

        # Find all SSRF destination URLs within the SSRF section only
        destinations = SSRF_URL_PATTERN.findall(ssrf_section)
        category = "destination"

        for url in destinations:
            rule_counter[category] = rule_counter.get(category, 0) + 1
            rule_id = f"h1-rule-{category}-{rule_counter[category]}"

            facts.rule_candidates.append(RuleCandidate(
                rule_id=rule_id,
                category=category,
                decision="allow",
                subject=url,
                constraints={"ssrf_only": True, "ssrf_sheriff": True},
                origin_type="policy_text",
                specificity="exact",
                source_ref="policy.md",
            ))

        # Add SSRF deny-other rule
        if destinations and SSRF_DENY_OTHER.search(text):
            rule_counter[category] = rule_counter.get(category, 0) + 1
            rule_id = f"h1-rule-{category}-{rule_counter[category]}"

            facts.rule_candidates.append(RuleCandidate(
                rule_id=rule_id,
                category=category,
                decision="deny",
                subject="ssrf_other",
                constraints={"ssrf_only": True},
                origin_type="policy_text",
                specificity="broad",
                source_ref="policy.md",
            ))

    # ---- Review candidate generation -----------------------------------------

    def _generate_review_candidates(self, facts: NormalizedFacts) -> None:
        """Generate review candidates for ambiguities.

        Triggers:
        - Wildcard allow + explicit deny row on same family
        - Temporal exclusion + CSV deny mismatch
        - Timezone parse inability
        - Ambiguous text not mappable to runtime guard
        """
        review_counter: dict[str, int] = {}

        # 1. Wildcard allow + explicit deny on same domain family
        self._check_wildcard_deny_conflicts(facts, review_counter)

        # 2. Temporal exclusion mismatch between policy and CSV
        self._check_temporal_exclusion_mismatch(facts, review_counter)

        # 3. Timezone parse check for policy text
        self._check_timezone_ambiguity(facts, review_counter)

        facts.add_audit("generate_review_candidates", "ok",
                        f"Generated {len(facts.review_candidates)} review candidates")

    def _check_wildcard_deny_conflicts(
        self, facts: NormalizedFacts, counter: dict[str, int]
    ) -> None:
        """Detect wildcard allow + explicit deny on same domain family."""
        # Group assets by domain family (TLD+1)
        allow_wildcards: list[NormalizedAsset] = []
        deny_assets: list[NormalizedAsset] = []

        for a in facts.assets:
            if a.asset_kind == "host_wildcard" and a.submission_allowed:
                allow_wildcards.append(a)
            if not a.submission_allowed and a.asset_kind in ("host_exact", "host_wildcard"):
                deny_assets.append(a)

        # Check if any deny asset falls under an allow wildcard
        for allow_asset in allow_wildcards:
            allow_root = self._extract_domain_root(allow_asset.canonical_key)
            for deny_asset in deny_assets:
                deny_key = deny_asset.canonical_key or deny_asset.raw_identifier
                if deny_key and allow_root and deny_key.endswith("." + allow_root):
                    # Direct suffix: e.g., developers.tiktok.com under *.tiktok.com
                    cat = "wildcard_deny_conflict"
                    counter[cat] = counter.get(cat, 0) + 1
                    finding_id = f"H1-{CATEGORY_SHORT.get(cat, 'WDC')}-{counter[cat]:03d}"

                    facts.review_candidates.append(ReviewCandidate(
                        finding_id=finding_id,
                        category=cat,
                        subject=f"{deny_asset.raw_identifier} under {allow_asset.raw_identifier}",
                        machine_guess={
                            "wildcard_allow": allow_asset.raw_identifier,
                            "explicit_deny": deny_asset.raw_identifier,
                            "effect": "deny",  # explicit deny overrides wildcard
                        },
                        risk_level="medium",
                        blocking=False,
                        recommended_override_path=f"overrides.scope.deny_hosts.add('{deny_asset.raw_identifier}')",
                        source_refs=[
                            allow_asset.source_ref,
                            deny_asset.source_ref,
                        ],
                    ))

    def _check_temporal_exclusion_mismatch(
        self, facts: NormalizedFacts, counter: dict[str, int]
    ) -> None:
        """Detect temporal exclusion text + CSV deny row inconsistency."""
        text = self._raw_policy

        # Look for temporal exclusion mentions
        temporal_pattern = re.compile(
            r"(?:temporar(?:y|ily)\s*excluded|temporary\s*exclusion|until\s*further\s*notice)",
            re.IGNORECASE,
        )
        if not temporal_pattern.search(text):
            return

        # Find matching deny assets (URL/host with eligible_for_submission=false)
        deny_assets = [
            a for a in facts.assets
            if not a.submission_allowed and a.asset_kind in ("host_exact", "host_wildcard")
        ]

        # Look for developer/minis path mentions in policy text
        minis_pattern = re.compile(r"developers?\.(?:tiktok|[\w.-]+)\.\w+(?:/minis)?", re.IGNORECASE)
        minis_matches = list(minis_pattern.finditer(text))

        if deny_assets and minis_matches:
            cat = "temporal_scope"
            counter[cat] = counter.get(cat, 0) + 1
            finding_id = f"H1-{CATEGORY_SHORT.get(cat, 'TMP')}-{counter[cat]:03d}"

            # Find the specific deny asset matching a minis-like host
            matching_assets = [
                a for a in deny_assets
                if any(m.group(0).lower() in (a.raw_identifier or "").lower()
                       for m in minis_matches)
            ]

            subject_asset = matching_assets[0].raw_identifier if matching_assets else deny_assets[0].raw_identifier

            facts.review_candidates.append(ReviewCandidate(
                finding_id=finding_id,
                category=cat,
                subject=f"Temporal exclusion for {subject_asset}",
                machine_guess={
                    "effect": "deny",
                    "temporal_match": [m.group(0) for m in minis_matches],
                },
                risk_level="high",
                blocking=True,
                recommended_override_path=f"overrides.scope.deny_url_prefixes.add('https://{subject_asset}/')",
                source_refs=[
                    "policy.md",
                    *(a.source_ref for a in (matching_assets or deny_assets[:1])),
                ],
            ))

    def _check_timezone_ambiguity(
        self, facts: NormalizedFacts, counter: dict[str, int]
    ) -> None:
        """Detect timezone references that may be ambiguous."""
        text = self._raw_policy

        # Look for timezone patterns like GMT+X or timezone abbreviations
        tz_pattern = re.compile(r"GMT[+-]\d{1,2}|UTC[+-]\d{1,2}|[A-Z]{3,4}\s*time", re.IGNORECASE)
        tz_matches = list(tz_pattern.finditer(text))

        if tz_matches:
            cat = "timezone_parse"
            counter[cat] = counter.get(cat, 0) + 1
            finding_id = f"H1-{CATEGORY_SHORT.get(cat, 'TZ')}-{counter[cat]:03d}"

            facts.review_candidates.append(ReviewCandidate(
                finding_id=finding_id,
                category=cat,
                subject=f"Timezone references found: {', '.join(m.group(0) for m in tz_matches[:3])}",
                machine_guess={
                    "timezone_refs": [m.group(0) for m in tz_matches],
                    "effect": "requires_hitl",
                },
                risk_level="medium",
                blocking=False,
                recommended_override_path="overrides.temporal.default_timezone",
                source_refs=["policy.md"],
            ))

    # ---- Helpers -------------------------------------------------------------

    @staticmethod
    def _extract_domain_root(host: str) -> str:
        """Extract TLD+1 root from a hostname.

        *.tiktok.com -> tiktok.com
        *.sub.example.com -> example.com
        example.com -> example.com
        """
        h = host.strip().lower()
        # Remove wildcard prefix
        if h.startswith("*."):
            h = h[2:]
        # Simple: take last two parts
        parts = h.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return h
