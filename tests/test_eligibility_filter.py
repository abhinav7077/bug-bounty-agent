"""Eligibility pre-filter + retest-queue contracts (skills/eligibility_filter.py)."""
import json

from skills.eligibility_filter import (
    _DEFAULT_LOW_VALUE_CATEGORIES,
    check_eligibility,
    get_retest_queue,
    queue_for_retest,
)


def test_unknown_category_is_eligible():
    result = check_eligibility.invoke({"vuln_category": "sql_injection"})
    assert result["eligible"] is True
    assert result["requires_human_review"] is False


def test_builtin_low_value_category_is_rejected_without_impact():
    result = check_eligibility.invoke({"vuln_category": "self_xss"})
    assert result["eligible"] is False
    assert result["requires_human_review"] is False


def test_low_value_category_with_demonstrated_impact_goes_to_human():
    result = check_eligibility.invoke(
        {"vuln_category": "self_xss", "has_demonstrated_impact": True}
    )
    # Not auto-rejected, but must not be auto-confirmed either.
    assert result["eligible"] is True
    assert result["requires_human_review"] is True


def test_program_specific_exclusion_is_honored():
    # A category not on the built-in list, excluded only by this program.
    result = check_eligibility.invoke(
        {
            "vuln_category": "open_redirect",
            "program_excluded_categories": ["open_redirect"],
        }
    )
    assert result["eligible"] is False


def test_category_matching_is_case_insensitive():
    result = check_eligibility.invoke({"vuln_category": "  SELF_XSS  "})
    assert result["eligible"] is False


def test_every_builtin_category_has_a_note():
    assert all(_DEFAULT_LOW_VALUE_CATEGORIES.values())


# --- retest queue roundtrip (writes under settings.SESSIONS_DIR) -------------

def test_retest_queue_roundtrip(tmp_path, monkeypatch):
    # SESSIONS_DIR is relative ("sessions"); run from a tmp cwd so the queue
    # file is written there and cleaned up with the tmp dir.
    monkeypatch.chdir(tmp_path)

    empty = get_retest_queue.invoke({"target": "example.com"})
    assert empty == []

    queued = queue_for_retest.invoke(
        {
            "target": "example.com",
            "finding_id": "F-1",
            "vuln_type": "idor",
            "resolved_on": "2026-01-01",
            "notes": "patched, worth a bypass retest",
        }
    )
    assert queued["queued"] is True
    assert queued["queue_size"] == 1

    loaded = get_retest_queue.invoke({"target": "example.com"})
    assert len(loaded) == 1
    assert loaded[0]["finding_id"] == "F-1"
    assert loaded[0]["vuln_type"] == "idor"

    # A second queue call appends rather than overwrites.
    queue_for_retest.invoke(
        {
            "target": "example.com",
            "finding_id": "F-2",
            "vuln_type": "ssrf",
            "resolved_on": "2026-02-01",
        }
    )
    on_disk = json.loads((tmp_path / "sessions" / "example.com" / "retest_queue.json").read_text())
    assert [row["finding_id"] for row in on_disk] == ["F-1", "F-2"]
