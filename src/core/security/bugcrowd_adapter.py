"""
Bugcrowd Program Adapter.

Reads a Bugcrowd provider bundle (policy.md + optional scope_assets.txt)
and produces provider-neutral NormalizedFacts.

Contract defined in:
  docs/shigoku/specs/2026-07-01_sgk-2026-0335_bug-bounty-program-bundle-guard-policy-contract.md
  Sections 6.3, 6.3.1-6.3.6
"""
from __future__ import annotations

import re
from typing import Optional

from src.core.security.program_adapter_base import (
    NormalizedAsset,
    NormalizedFacts,
    ProgramAdapterBase,
    ReviewCandidate,
    RuleCandidate,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Regex to identify a Markdown header line (ATX-style)
_HEADER_RE = re.compile(r"^(#{1,6})\s+(.+)$")

# Regex to extract backtick-quoted text
_BACKTICK_RE = re.compile(r"`([^`]+)`")

# Regex for detecting an explicit URL (starts with https?://)
_URL_RE = re.compile(r"^https?://")


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class BugcrowdAdapter(ProgramAdapterBase):
    """Bugcrowd provider adapter.

    Extracts assets from the ``Targets`` section of policy.md and
    generates rule candidates from explicit policy text (DoS, rate-limit
    bypass, post-exploit, auth, third-party services, N-day).
    """

    ADAPTER_NAME: str = "bugcrowd_program_adapter"
    ADAPTER_VERSION: int = 1
    PROVIDER: str = "bugcrowd"

    # ---- Provider-specific fact extraction --------------------------------

    def _extract_provider_facts(self, facts: NormalizedFacts) -> None:
        """Provider-specific extraction for Bugcrowd bundles."""
        # Program identity
        facts.program["program_name"] = self._manifest.get("program_name", "")

        # --- Assets: extract from Targets section --------------------------
        self._extract_targets_assets(facts)

        # --- Rule candidates: extract from policy text --------------------
        self._extract_text_rules(facts)

    # ---- Asset extraction -------------------------------------------------

    def _extract_targets_assets(self, facts: NormalizedFacts) -> None:
        """Parse the ``## Targets`` (or ``# Targets``) section for exact hosts/URLs.

        For each listed item:
        - host-only  -> ``host_exact``, ``submission_allowed=true``
        - ``https://`` -> ``url_prefix``, ``submission_allowed=true``
        """
        targets_text = self._extract_section("Targets")
        if not targets_text:
            facts.add_audit(
                "extract_targets", "warning",
                "Targets section not found in policy.md",
            )
            return

        counter = 0
        for line in targets_text.splitlines():
            # Match items in backticks — these are the listed targets
            matches = _BACKTICK_RE.findall(line)
            for match in matches:
                raw = match.strip()
                if not raw:
                    continue
                counter += 1
                asset = self._make_asset(raw, counter, "policy.md#targets")
                facts.assets.append(asset)

        facts.add_audit(
            "extract_targets", "ok",
            f"Extracted {counter} asset(s) from Targets section",
        )

    def _make_asset(self, raw: str, counter: int, source_ref: str) -> NormalizedAsset:
        """Create a NormalizedAsset from a raw identifier."""
        stripped = raw.strip()
        if _URL_RE.match(stripped):
            asset_kind = "url_prefix"
            canonical = stripped
        else:
            asset_kind = "host_exact"
            canonical = stripped.lower()

        return NormalizedAsset(
            asset_id=f"bc-asset-{counter}",
            raw_identifier=stripped,
            canonical_key=canonical,
            asset_kind=asset_kind,
            runtime_surface="http",
            submission_allowed=True,
            bounty_allowed=False,
            max_severity="none",
            source_ref=source_ref,
        )

    # ---- Section extraction utility ---------------------------------------

    def _extract_section(self, section_name: str) -> str:
        """Extract the content of a named Markdown section (e.g. ``Targets``).

        Returns the text between the matching header (any level) and the
        next header of equal or higher level, or the end of the document.
        """
        text = self._raw_policy
        lines = text.splitlines()
        header_level: Optional[int] = None
        target_started = False
        output: list[str] = []
        name_lower = section_name.lower()

        for line in lines:
            m = _HEADER_RE.match(line)
            if m:
                level = len(m.group(1))
                title = m.group(2).strip()
                if target_started:
                    # Stop at next header of same or higher level
                    assert header_level is not None  # set when target_started=True
                    if level <= header_level:
                        break
                    output.append(line)
                elif title.lower().startswith(name_lower):
                    header_level = level
                    target_started = True
                    # Include the header line itself
                    output.append(line)
            elif target_started:
                output.append(line)

        return "\n".join(output)

    # ---- Text-based rule extraction --------------------------------------

    def _extract_text_rules(self, facts: NormalizedFacts) -> None:
        """Extract rule candidates from policy text.

        Uses keyword / section matching — no AI/LLM.
        """
        text = self._raw_policy
        text_lower = text.lower()
        counter = 0

        # --- Third party providers and services -> deny -------------------
        if "third party providers" in text_lower:
            counter += 1
            facts.rule_candidates.append(RuleCandidate(
                rule_id=f"bc-rule-destination-{counter}",
                category="destination",
                decision="deny",
                subject="third_party_services",
                origin_type="policy_text",
                specificity="medium",
                source_ref="policy.md#out-of-scope",
            ))

        # --- Post-exploit -> phase:post_exploit=deny ----------------------
        if "stop testing and submit" in text_lower or "post-exploitation" in text_lower:
            counter += 1
            facts.rule_candidates.append(RuleCandidate(
                rule_id=f"bc-rule-phase-{counter}",
                category="phase",
                decision="deny",
                subject="post_exploit",
                origin_type="policy_text",
                specificity="medium",
                source_ref="policy.md#post-exploitation",
            ))

        # --- DoS/DDoS -> attack_class:dos=deny ----------------------------
        if re.search(r"dos\b|ddos|network dos", text_lower):
            counter += 1
            facts.rule_candidates.append(RuleCandidate(
                rule_id=f"bc-rule-attack_class-{counter}",
                category="attack_class",
                decision="deny",
                subject="dos",
                origin_type="policy_text",
                specificity="medium",
                source_ref="policy.md#excluded-submission-types",
            ))

        # --- Rate limiting bypass -> attack_class:rate_limit_bypass=deny --
        if "rate limiting bypass" in text_lower:
            counter += 1
            facts.rule_candidates.append(RuleCandidate(
                rule_id=f"bc-rule-attack_class-{counter}",
                category="attack_class",
                decision="deny",
                subject="rate_limit_bypass",
                origin_type="policy_text",
                specificity="medium",
                source_ref="policy.md#excluded-submission-types",
            ))

        # --- Auth: @bugcrowdninja.com -> auth rule ------------------------
        email_match = re.search(
            r"@bugcrowdninja\.com",
            text,
            re.IGNORECASE,
        )
        if email_match:
            counter += 1
            facts.rule_candidates.append(RuleCandidate(
                rule_id=f"bc-rule-auth-{counter}",
                category="auth",
                decision="allow",  # allows testing if you have that domain
                subject="allowed_email_domain",
                constraints={"allowed_email_domains": ["bugcrowdninja.com"]},
                origin_type="policy_text",
                specificity="exact",
                source_ref="policy.md#credentials",
            ))

        # --- Infrastructure-level attacks -> deny (out of scope) ----------
        if "infrastructure-level" in text_lower:
            counter += 1
            facts.rule_candidates.append(RuleCandidate(
                rule_id=f"bc-rule-attack_class-{counter}",
                category="attack_class",
                decision="deny",
                subject="infrastructure_attack",
                origin_type="policy_text",
                specificity="medium",
                source_ref="policy.md#out-of-scope",
            ))

        facts.add_audit(
            "extract_text_rules", "ok",
            f"Extracted {counter} text-based rule candidate(s)",
        )

    # ---- Review candidate generation --------------------------------------

    def _generate_review_candidates(self, facts: NormalizedFacts) -> None:
        """Generate review candidates for ambiguous situations.

        Per spec 6.3.5:
        - N-day determination needing external info
        - Focus Area ambiguity (allow vs merely preferred)
        - Credential requirement ambiguity (email domain vs invite-only)
        - Host vs path ambiguity in Targets
        """
        text = self._raw_policy
        text_lower = text.lower()
        rc_counter = 0

        # --- N-day ambiguity -----------------------------------------------
        if "n-day" in text_lower and "14 days" in text_lower:
            rc_counter += 1
            facts.review_candidates.append(ReviewCandidate(
                finding_id=f"BC-NDAY-{rc_counter:03d}",
                category="attack_class",
                subject="third_party_n_day",
                machine_guess={
                    "decision": "deny",
                    "trigger": "disclosed_less_than_14_days_ago",
                    "condition": "N-day disclosed < 14 days ago -> deny",
                },
                risk_level="medium",
                blocking=False,
                recommended_override_path="attack_classes.third_party_n_day",
                source_refs=["policy.md#n-day--third-party-0-day-policy"],
            ))

        # --- Focus Area ambiguity ------------------------------------------
        if "focus areas" in text_lower:
            rc_counter += 1
            facts.review_candidates.append(ReviewCandidate(
                finding_id=f"BC-FOCUS-{rc_counter:03d}",
                category="scope_interpretation",
                subject="focus_areas_ambiguity",
                machine_guess={
                    "effect": "preferred_only",
                    "note": "Focus Areas are hints, not allow rules. "
                            "Review whether any Focus Area should expand scope.",
                },
                risk_level="low",
                blocking=False,
                recommended_override_path="scope.focus_area_allow",
                source_refs=["policy.md#focus-areas"],
            ))

        # --- Credential ambiguity ------------------------------------------
        if "@bugcrowdninja.com" in text_lower:
            rc_counter += 1
            facts.review_candidates.append(ReviewCandidate(
                finding_id=f"BC-CRED-{rc_counter:03d}",
                category="auth",
                subject="credential_requirement_ambiguity",
                machine_guess={
                    "effect": "email_domain_restriction",
                    "note": "Policy requires @bugcrowdninja.com email. "
                            "Review whether this is the ONLY requirement "
                            "or if invite/approval is also needed.",
                },
                risk_level="medium",
                blocking=False,
                recommended_override_path="auth.credential_mode",
                source_refs=["policy.md#credentials"],
            ))

        # --- Host vs path ambiguity in Targets -----------------------------
        # Check if any parsed asset looks ambiguous (host-only but could need a path)
        ambiguous_targets = [
            a for a in facts.assets
            if a.asset_kind in ("host_exact", "url_prefix")
        ]
        if ambiguous_targets:
            rc_counter += 1
            facts.review_candidates.append(ReviewCandidate(
                finding_id=f"BC-TARG-{rc_counter:03d}",
                category="scope_interpretation",
                subject="target_host_path_ambiguity",
                machine_guess={
                    "note": "Targets are exact hosts. Verify no path-level scope "
                            "restriction is intended beyond the listed hosts.",
                },
                risk_level="low",
                blocking=False,
                recommended_override_path="scope.url_prefixes",
                source_refs=["policy.md#targets"],
            ))
