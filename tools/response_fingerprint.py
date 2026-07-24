"""Response-comparison primitives shared by anything that needs to tell a
genuinely different result apart from an error page, a catch-all, or noise.

Plain functions only, no @tool decoration — like skills/hitl_batcher.py,
this is a helper module consumed by other skills (skills/auth_mapper.py is
the first caller), NOT something the model calls directly. Don't add
anything from this file to agent/orchestrator.py's ALL_TOOLS.

The core problem every function here solves: a raw status-code or
length check produces false positives constantly (soft-404 catch-all pages,
per-request volatile fields like timestamps/request-ids, single-sample
timing jitter). Each function strips out the specific kind of noise that
would otherwise make a real signal indistinguishable from normal variance.
"""
import difflib
import math
import re
import statistics

_VOLATILE_FIELD_RE = re.compile(
    r'"(?:timestamp|date|time|request_id|trace_id|requestid|traceid|nonce|instance)"\s*:\s*"[^"]*"',
    re.IGNORECASE,
)
_DIGIT_RUN_RE = re.compile(r"\d{4,}")


def normalize_body(body: str) -> str:
    """Strip fields that vary per-request but don't reflect a real content difference."""
    stripped = _VOLATILE_FIELD_RE.sub("", body)
    return _DIGIT_RUN_RE.sub("<N>", stripped)


def similarity(a: str, b: str) -> float:
    """Structural similarity of two response bodies, after normalization. 0..1."""
    return difflib.SequenceMatcher(None, normalize_body(a), normalize_body(b)).quick_ratio()


def responses_equivalent(body_a: str, body_b: str, threshold: float = 0.95) -> bool:
    """True if two bodies look like the same underlying object/page."""
    return similarity(body_a, body_b) >= threshold


def is_distinct_object(baseline_body: str, candidate_body: str) -> bool:
    """True if `candidate_body` looks like a genuinely different real object,
    not an error page, empty shell, or near-duplicate of the baseline.

    Two ways to qualify: clearly dissimilar (sim < 0.98), or moderately
    dissimilar with enough raw length difference to rule out incidental
    whitespace/field-ordering noise (delta >= 64 bytes and sim < 0.9).
    """
    sim = similarity(baseline_body, candidate_body)
    if sim < 0.98:
        return True
    return len(candidate_body) - len(baseline_body) >= 64 and sim < 0.9


def is_soft_404(status: int, body: str, baseline_probes: list[tuple[int, str]]) -> bool:
    """True if (status, body) matches one of the host's own known-nonexistent-path
    responses closely enough to be a catch-all page, not a real hit.

    `baseline_probes` is a list of (status, body) pairs collected by the
    caller from a couple of random, definitely-nonexistent paths on the same
    host up front — this function makes no requests itself.
    """
    return any(status == base_status and similarity(body, base_body) >= 0.90
               for base_status, base_body in baseline_probes)


def confirm_timing(
    payload_samples: list[float], control_samples: list[float],
    floor_s: float, ratio: float = 2.5,
) -> bool:
    """Median-of-samples timing confirmation for blind SQLi/command-injection.

    A single slow response proves nothing (network jitter, GC pause, a slow
    neighboring request). Requires the payload's median latency to clear an
    absolute floor (the injected delay itself, e.g. 2.8s for a SLEEP(3)
    payload) AND beat the control median by `ratio` — both gates together
    rule out "the whole site is just slow right now."
    """
    if not payload_samples or not control_samples:
        return False
    payload_median = statistics.median(payload_samples)
    control_median = statistics.median(control_samples)
    if payload_median < floor_s:
        return False
    if control_median <= 0:
        return True
    return payload_median >= control_median * ratio


_PLACEHOLDER_RE = re.compile(r"^(example|xxx+|changeme|your[-_]?\w+|<[^>]+>|redacted|\*+)$", re.IGNORECASE)
_STRUCTURAL_SECRET_PREFIXES = ("AKIA", "ASIA", "AIza", "sk_live_", "sk_test_", "xox", "ghp_", "gho_", "-----BEGIN")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def looks_like_real_secret(value: str, min_entropy: float = 3.0) -> bool:
    """Gate a regex-matched candidate before reporting it as a real secret.

    A bare regex match on "api_key=..." fires constantly on placeholder/
    documentation/test values. Accept only if the value has enough entropy
    to plausibly be random-generated material, or starts with a structurally
    unambiguous real-credential prefix (AWS/GCP/Slack/Stripe/GitHub/PEM) —
    and always reject an obvious placeholder regardless of entropy.
    """
    if _PLACEHOLDER_RE.match(value.strip()):
        return False
    if value.startswith(_STRUCTURAL_SECRET_PREFIXES):
        return True
    return shannon_entropy(value) >= min_entropy
