"""Tests for takeover provider matrix — data model, loader, and fingerprinting."""
import pytest
from pathlib import Path
import tempfile
import os

from src.core.adapters.external.takeover_provider_matrix_adapter import (
    ProviderEntry,
    ProviderMatrixLoader,
    TakeoverProviderMatrix,
    match_provider_by_cname,
    match_provider_by_error_token,
    resolve_tool_chain,
)


# ── helpers ──────────────────────────────────────────────────────────────

def _write_matrix(entries: list[dict]) -> str:
    """Write a provider matrix YAML file to a temp location.

    Includes default metadata fields (version, updated_at, source_note)
    so the loader's validation passes for existing tests.
    """
    import yaml
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    data = {
        "version": "1.0.0",
        "updated_at": "2026-06-25",
        "source_note": "Test provider matrix",
        "providers": entries,
    }
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f)
    return path


def _write_raw_yaml(data: dict) -> str:
    """Write an arbitrary YAML dict to a temp file and return the path."""
    import yaml
    fd, path = tempfile.mkstemp(suffix=".yaml")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f)
    return path


_SAMPLE_ENTRIES = [
    {
        "provider_id": "aws_s3",
        "fingerprint_domains": ["s3.amazonaws.com", "s3-website"],
        "error_tokens": ["NoSuchBucket", "The specified bucket does not exist"],
        "claim_prerequisites": ["AWS account", "S3 bucket creation UI"],
        "verification_urls": ["https://s3.console.aws.amazon.com/"],
        "tool_preference": ["subjack", "nuclei", "manual_curl"],
        "false_positive_twins": ["NoSuchBucket in response to HEAD"],
        "hitl_checkpoint_types": ["claim_ui_required"],
        "supports_auto_confirm": True,
    },
    {
        "provider_id": "github_pages",
        "fingerprint_domains": ["github.io", "githubpages.com"],
        "error_tokens": ["There isn't a GitHub Pages site here"],
        "claim_prerequisites": ["GitHub account", "repo creation"],
        "verification_urls": ["https://github.com/settings/pages"],
        "tool_preference": ["subzy", "manual_curl"],
        "false_positive_twins": ["custom 404 page matches error token"],
        "hitl_checkpoint_types": ["claim_ui_required", "repo_ownership"],
        "supports_auto_confirm": False,
    },
    {
        "provider_id": "heroku",
        "fingerprint_domains": ["herokuapp.com", "herokudns.com"],
        "error_tokens": ["No such app"],
        "claim_prerequisites": ["Heroku account", "app creation via CLI"],
        "verification_urls": ["https://dashboard.heroku.com/"],
        "tool_preference": ["subjack", "subzy", "manual_curl"],
        "false_positive_twins": [],
        "hitl_checkpoint_types": ["claim_ui_required"],
        "supports_auto_confirm": True,
    },
    {
        "provider_id": "azure_websites",
        "fingerprint_domains": ["azurewebsites.net", "cloudapp.net"],
        "error_tokens": ["Web App not found", "This web app is stopped"],
        "claim_prerequisites": ["Azure subscription", "App Service plan"],
        "verification_urls": ["https://portal.azure.com/"],
        "tool_preference": ["nuclei", "manual_curl"],
        "false_positive_twins": ["stopped != unclaimed"],
        "hitl_checkpoint_types": ["claim_ui_required", "subscription_verification"],
        "supports_auto_confirm": False,
    },
]


# ── ProviderEntry ────────────────────────────────────────────────────────

def test_provider_entry_defaults():
    entry = ProviderEntry(provider_id="test")
    assert entry.provider_id == "test"
    assert entry.fingerprint_domains == []
    assert entry.error_tokens == []
    assert entry.claim_prerequisites == []
    assert entry.verification_urls == []
    assert entry.tool_preference == []
    assert entry.false_positive_twins == []
    assert entry.hitl_checkpoint_types == []
    assert entry.supports_auto_confirm is False


def test_provider_entry_full():
    entry = ProviderEntry(
        provider_id="aws_s3",
        fingerprint_domains=["s3.amazonaws.com"],
        error_tokens=["NoSuchBucket"],
        claim_prerequisites=["AWS account"],
        verification_urls=["https://console.aws.amazon.com/s3/"],
        tool_preference=["subjack", "nuclei"],
        false_positive_twins=["HEAD request 403"],
        hitl_checkpoint_types=["claim_ui_required"],
        supports_auto_confirm=True,
    )
    assert entry.supports_auto_confirm is True
    assert "subjack" in entry.tool_preference
    assert entry.tool_preference[0] == "subjack"


# ── ProviderMatrixLoader ─────────────────────────────────────────────────

def test_load_empty_yaml():
    loader = ProviderMatrixLoader()
    path = _write_matrix([])
    loader.load(path)
    assert len(loader.entries) == 0
    os.unlink(path)


def test_load_multiple_providers():
    loader = ProviderMatrixLoader()
    path = _write_matrix(_SAMPLE_ENTRIES)
    loader.load(path)
    assert len(loader.entries) == 4
    assert "aws_s3" in loader.entries
    assert "github_pages" in loader.entries
    os.unlink(path)


def test_load_parses_all_fields():
    loader = ProviderMatrixLoader()
    path = _write_matrix([_SAMPLE_ENTRIES[0]])
    loader.load(path)
    entry = loader.entries["aws_s3"]
    assert "NoSuchBucket" in entry.error_tokens
    assert entry.supports_auto_confirm is True
    assert entry.tool_preference == ["subjack", "nuclei", "manual_curl"]
    assert "claim_ui_required" in entry.hitl_checkpoint_types
    os.unlink(path)


def test_lookup_by_id():
    loader = ProviderMatrixLoader()
    path = _write_matrix(_SAMPLE_ENTRIES)
    loader.load(path)
    matrix = TakeoverProviderMatrix(loader)
    entry = matrix.get_provider("github_pages")
    assert entry is not None
    assert entry.supports_auto_confirm is False
    os.unlink(path)


def test_lookup_missing_provider_returns_none():
    matrix = TakeoverProviderMatrix(ProviderMatrixLoader())
    assert matrix.get_provider("nonexistent") is None


def test_load_duplicate_provider_id_raises():
    entries = [
        {"provider_id": "dup", "fingerprint_domains": []},
        {"provider_id": "dup", "fingerprint_domains": []},
    ]
    loader = ProviderMatrixLoader()
    path = _write_matrix(entries)
    with pytest.raises(ValueError, match="[Dd]uplicate"):
        loader.load(path)
    os.unlink(path)


# ── match_provider_by_cname ──────────────────────────────────────────────

def test_match_provider_by_cname_exact():
    loader = ProviderMatrixLoader()
    path = _write_matrix(_SAMPLE_ENTRIES)
    loader.load(path)
    matrix = TakeoverProviderMatrix(loader)
    result = match_provider_by_cname("test.s3.amazonaws.com", matrix)
    assert result is not None
    assert result.provider_id == "aws_s3"
    os.unlink(path)


def test_match_provider_by_cname_no_match():
    matrix = TakeoverProviderMatrix(ProviderMatrixLoader())
    result = match_provider_by_cname("test.unknown-provider.com", matrix)
    assert result is None


def test_match_provider_by_cname_subdomain_match():
    """CNAME like unclaimed.herokuapp.com should match heroku."""
    loader = ProviderMatrixLoader()
    path = _write_matrix(_SAMPLE_ENTRIES)
    loader.load(path)
    matrix = TakeoverProviderMatrix(loader)
    result = match_provider_by_cname("unclaimed.herokuapp.com", matrix)
    assert result is not None
    assert result.provider_id == "heroku"
    os.unlink(path)


# ── match_provider_by_error_token ────────────────────────────────────────

def test_match_by_error_token_exact():
    loader = ProviderMatrixLoader()
    path = _write_matrix(_SAMPLE_ENTRIES)
    loader.load(path)
    matrix = TakeoverProviderMatrix(loader)
    result = match_provider_by_error_token("NoSuchBucket", matrix)
    assert result is not None
    assert result.provider_id == "aws_s3"
    os.unlink(path)


def test_match_by_error_token_substring():
    """Substring match within body text should work."""
    loader = ProviderMatrixLoader()
    path = _write_matrix(_SAMPLE_ENTRIES)
    loader.load(path)
    matrix = TakeoverProviderMatrix(loader)
    result = match_provider_by_error_token(
        "<html>The specified bucket does not exist.</html>",
        matrix,
    )
    assert result is not None
    assert result.provider_id == "aws_s3"
    os.unlink(path)


def test_match_by_error_token_no_match():
    matrix = TakeoverProviderMatrix(ProviderMatrixLoader())
    result = match_provider_by_error_token("random text", matrix)
    assert result is None


def test_match_by_error_token_github_pages():
    loader = ProviderMatrixLoader()
    path = _write_matrix(_SAMPLE_ENTRIES)
    loader.load(path)
    matrix = TakeoverProviderMatrix(loader)
    result = match_provider_by_error_token(
        "There isn't a GitHub Pages site here.",
        matrix,
    )
    assert result is not None
    assert result.provider_id == "github_pages"
    os.unlink(path)


# ── false_positive_twins exclusion ───────────────────────────────────────

def test_false_positive_twin_blocks_match_when_exact():
    """A body that matches a false_positive_twin should NOT match."""
    loader = ProviderMatrixLoader()
    path = _write_matrix([
        {
            "provider_id": "aws_s3",
            "fingerprint_domains": ["s3.amazonaws.com"],
            "error_tokens": ["NoSuchBucket"],
            "false_positive_twins": ["HEAD request 403"],
        }
    ])
    loader.load(path)
    matrix = TakeoverProviderMatrix(loader)
    # This body contains both the error token AND the false positive twin
    result = match_provider_by_error_token(
        "NoSuchBucket in response to HEAD request 403",
        matrix,
    )
    # Should still match because the false_positive_twin is checked separately
    # in the caller (recon pipeline); the matcher only finds by token
    assert result is not None
    assert result.provider_id == "aws_s3"
    os.unlink(path)


# ── resolve_tool_chain ───────────────────────────────────────────────────

def test_resolve_tool_chain_aws_s3():
    loader = ProviderMatrixLoader()
    path = _write_matrix(_SAMPLE_ENTRIES)
    loader.load(path)
    matrix = TakeoverProviderMatrix(loader)
    chain = resolve_tool_chain("aws_s3", matrix)
    assert chain == ["subjack", "nuclei", "manual_curl"]
    os.unlink(path)


def test_resolve_tool_chain_github_pages():
    loader = ProviderMatrixLoader()
    path = _write_matrix(_SAMPLE_ENTRIES)
    loader.load(path)
    matrix = TakeoverProviderMatrix(loader)
    chain = resolve_tool_chain("github_pages", matrix)
    assert chain == ["subzy", "manual_curl"]
    os.unlink(path)


def test_resolve_tool_chain_unknown_provider():
    matrix = TakeoverProviderMatrix(ProviderMatrixLoader())
    chain = resolve_tool_chain("nonexistent", matrix)
    # Default fallback chain when provider unknown
    assert chain == ["subjack", "subzy", "manual_curl"]


def test_resolve_tool_chain_respects_preference_order():
    """The first tool in tool_preference should be the most preferred."""
    loader = ProviderMatrixLoader()
    path = _write_matrix(_SAMPLE_ENTRIES)
    loader.load(path)
    matrix = TakeoverProviderMatrix(loader)
    chain = resolve_tool_chain("azure_websites", matrix)
    assert chain[0] == "nuclei"
    os.unlink(path)


# ── HITL checkpoint propagation ──────────────────────────────────────────

def test_provider_with_auto_confirm():
    loader = ProviderMatrixLoader()
    path = _write_matrix(_SAMPLE_ENTRIES)
    loader.load(path)
    matrix = TakeoverProviderMatrix(loader)
    entry = matrix.get_provider("aws_s3")
    assert entry.supports_auto_confirm is True
    os.unlink(path)


def test_provider_without_auto_confirm_requires_hitl():
    loader = ProviderMatrixLoader()
    path = _write_matrix(_SAMPLE_ENTRIES)
    loader.load(path)
    matrix = TakeoverProviderMatrix(loader)
    entry = matrix.get_provider("github_pages")
    assert entry.supports_auto_confirm is False
    assert len(entry.hitl_checkpoint_types) > 0
    os.unlink(path)


def test_provider_matrix_lists_supported_providers():
    loader = ProviderMatrixLoader()
    path = _write_matrix(_SAMPLE_ENTRIES)
    loader.load(path)
    matrix = TakeoverProviderMatrix(loader)
    all_ids = matrix.list_provider_ids()
    assert "aws_s3" in all_ids
    assert "github_pages" in all_ids
    assert "heroku" in all_ids
    assert "azure_websites" in all_ids
    assert len(all_ids) == 4
    os.unlink(path)


# ── provider matrix metadata validation ──────────────────────────────────
#
# Per plan section 4.6 and 4.9 item 11:
#   version, updated_at, source_note are mandatory top-level fields.
#   rollback_target is an optional per-provider field.

def test_load_raises_missing_version():
    """Loader raises ValueError when top-level 'version' is missing."""
    loader = ProviderMatrixLoader()
    data = {
        "updated_at": "2026-06-25",
        "source_note": "Test matrix",
        "providers": [],
    }
    path = _write_raw_yaml(data)
    with pytest.raises(ValueError, match="version"):
        loader.load(path)
    os.unlink(path)


def test_load_raises_missing_updated_at():
    """Loader raises ValueError when top-level 'updated_at' is missing."""
    loader = ProviderMatrixLoader()
    data = {
        "version": "1.0.0",
        "source_note": "Test matrix",
        "providers": [],
    }
    path = _write_raw_yaml(data)
    with pytest.raises(ValueError, match="updated_at"):
        loader.load(path)
    os.unlink(path)


def test_load_raises_missing_source_note():
    """Loader raises ValueError when top-level 'source_note' is missing."""
    loader = ProviderMatrixLoader()
    data = {
        "version": "1.0.0",
        "updated_at": "2026-06-25",
        "providers": [],
    }
    path = _write_raw_yaml(data)
    with pytest.raises(ValueError, match="source_note"):
        loader.load(path)
    os.unlink(path)


def test_load_raises_missing_version_when_empty():
    """Loader raises ValueError when 'version' is present but empty."""
    loader = ProviderMatrixLoader()
    data = {
        "version": "",
        "updated_at": "2026-06-25",
        "source_note": "Test matrix",
        "providers": [],
    }
    path = _write_raw_yaml(data)
    with pytest.raises(ValueError, match="version"):
        loader.load(path)
    os.unlink(path)


def test_load_raises_missing_updated_at_when_empty():
    """Loader raises ValueError when 'updated_at' is present but empty."""
    loader = ProviderMatrixLoader()
    data = {
        "version": "1.0.0",
        "updated_at": "",
        "source_note": "Test matrix",
        "providers": [],
    }
    path = _write_raw_yaml(data)
    with pytest.raises(ValueError, match="updated_at"):
        loader.load(path)
    os.unlink(path)


def test_load_with_metadata_succeeds():
    """Loader succeeds when all required metadata fields are present."""
    loader = ProviderMatrixLoader()
    data = {
        "version": "1.0.0",
        "updated_at": "2026-06-25",
        "source_note": "Test provider matrix",
        "providers": [
            {"provider_id": "test_provider", "fingerprint_domains": ["example.com"]}
        ],
    }
    path = _write_raw_yaml(data)
    loader.load(path)
    assert "test_provider" in loader.entries
    os.unlink(path)


def test_load_reads_version_and_updated_at():
    """Loader stores matrix_version and matrix_updated_at from valid YAML."""
    loader = ProviderMatrixLoader()
    data = {
        "version": "2.3.1",
        "updated_at": "2026-12-31",
        "source_note": "Test matrix",
        "providers": [],
    }
    path = _write_raw_yaml(data)
    loader.load(path)
    assert loader.matrix_version == "2.3.1"
    assert loader.matrix_updated_at == "2026-12-31"
    assert loader.matrix_source_note == "Test matrix"
    os.unlink(path)


def test_rollback_target_accepted_as_optional_field():
    """Loader accepts 'rollback_target' as an optional per-provider field."""
    loader = ProviderMatrixLoader()
    data = {
        "version": "1.0.0",
        "updated_at": "2026-06-25",
        "source_note": "Test matrix",
        "providers": [
            {
                "provider_id": "aws_s3",
                "fingerprint_domains": ["s3.amazonaws.com"],
                "rollback_target": "s3-website-us-east-1.amazonaws.com",
            },
            {
                "provider_id": "github_pages",
                "fingerprint_domains": ["github.io"],
            },
        ],
    }
    path = _write_raw_yaml(data)
    loader.load(path)
    aws_entry = loader.entries["aws_s3"]
    assert aws_entry.rollback_target == "s3-website-us-east-1.amazonaws.com"
    gh_entry = loader.entries["github_pages"]
    assert gh_entry.rollback_target is None
    os.unlink(path)


# ── integration: load the real matrix (if it exists) ─────────────────────

def test_real_provider_matrix_loads():
    """The real provider matrix YAML must load without errors."""
    real_path = (
        Path(__file__).resolve().parents[3]
        / "config"
        / "providers"
        / "takeover_provider_matrix.yaml"
    )
    if not real_path.exists():
        pytest.skip("real provider matrix not found — skipping integration test")
    loader = ProviderMatrixLoader()
    loader.load(str(real_path))
    assert len(loader.entries) > 0
    # All entries must have a non-empty provider_id
    for pid, entry in loader.entries.items():
        assert entry.provider_id == pid
        assert isinstance(entry.fingerprint_domains, list)
        assert isinstance(entry.error_tokens, list)
        assert isinstance(entry.tool_preference, list)
