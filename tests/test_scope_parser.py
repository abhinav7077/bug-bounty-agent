"""Scope-parsing + scope-fabrication-gate contracts (skills/scope_parser.py).

Two safety-critical behaviors are pinned here:
  1. looks_like_scope_text() — the structural gate that stops the model from
     fabricating a scope policy. It must pass real multi-domain policy text and
     reject a bare "is X in scope?" instruction that names a single domain.
  2. parse_scope() — section classification (in/out), forbidden-wins, prose on
     one line, payout-tier extraction, and VDP detection.
"""
from skills.scope_parser import (
    _domain_matches,
    check_scope,
    looks_like_scope_text,
    parse_scope,
    parse_scope_policy,
)


# --- looks_like_scope_text: the fabrication gate -----------------------------

def test_single_domain_instruction_does_not_look_like_scope():
    # The exact failure case the gate exists for: naming one target, no policy.
    assert looks_like_scope_text("is api.hackerone.com in scope?") is False


def test_real_policy_with_marker_and_two_domains_passes():
    assert looks_like_scope_text("In scope: a.example.com and b.example.com") is True


def test_two_domains_but_no_marker_is_rejected():
    assert looks_like_scope_text("a.example.com and b.example.com") is False


def test_marker_but_only_one_domain_is_rejected():
    assert looks_like_scope_text("The following is in scope: only.example.com") is False


def test_inline_policy_in_a_compound_command_passes():
    text = (
        "is www.example.com in scope, given this policy text: "
        "In scope: www.example.com, api.example.com. Out of scope: internal.example.com."
    )
    assert looks_like_scope_text(text) is True


# --- parse_scope: classification + extraction --------------------------------

def test_in_and_out_of_scope_sections_split_correctly():
    policy = parse_scope(
        "In scope:\nexample.com\napi.example.com\nOut of scope:\ninternal.example.com"
    )
    assert "example.com" in policy.allowed_domains
    assert "api.example.com" in policy.allowed_domains
    assert "internal.example.com" in policy.forbidden_domains
    assert "internal.example.com" not in policy.allowed_domains


def test_prose_on_one_line_is_still_split_by_markers():
    # The _force_markers_onto_own_lines path: both sections on a single line.
    policy = parse_scope("In scope: example.com. Out of scope: internal.example.com.")
    assert "example.com" in policy.allowed_domains
    assert "internal.example.com" in policy.forbidden_domains


def test_forbidden_always_wins_over_allowed():
    # Same domain appears under both headings -> forbidden must win.
    policy = parse_scope("In scope: dup.example.com\nOut of scope: dup.example.com")
    assert "dup.example.com" in policy.forbidden_domains
    assert "dup.example.com" not in policy.allowed_domains


def test_payout_tiers_and_paid_program_type():
    policy = parse_scope("In scope: example.com\nCritical: $5,000\nHigh - $2000")
    assert policy.payout_tiers == {"critical": 5000.0, "high": 2000.0}
    assert policy.program_type == "paid"


def test_vdp_only_program_detected():
    policy = parse_scope("In scope: example.com\nThis program offers no monetary reward.")
    assert policy.program_type == "vdp_no_reward"


def test_excluded_categories_pulled_from_policy_text():
    policy = parse_scope(
        "In scope: example.com\nWe do not accept self-XSS or missing security headers reports."
    )
    assert "self_xss" in policy.excluded_finding_categories
    assert "missing_security_headers" in policy.excluded_finding_categories


# --- check_scope + wildcard matching -----------------------------------------

def test_domain_matches_wildcard_and_apex():
    assert _domain_matches("sub.example.com", "*.example.com") is True
    assert _domain_matches("example.com", "*.example.com") is True  # apex folded in
    assert _domain_matches("sub.other.com", "*.example.com") is False
    assert _domain_matches("example.com", "example.com") is True


def test_check_scope_forbidden_beats_allowed_and_flags_unknown():
    policy = parse_scope_policy.invoke(
        {"scope_text": "In scope: example.com\nOut of scope: evil.example.com"}
    )

    forbidden = check_scope.invoke({"domain": "evil.example.com", "policy": policy})
    assert forbidden["in_scope"] is False
    assert forbidden["requires_human_confirm"] is False

    allowed = check_scope.invoke({"domain": "example.com", "policy": policy})
    assert allowed["in_scope"] is True

    unknown = check_scope.invoke({"domain": "unlisted.com", "policy": policy})
    assert unknown["in_scope"] is False
    assert unknown["requires_human_confirm"] is True
