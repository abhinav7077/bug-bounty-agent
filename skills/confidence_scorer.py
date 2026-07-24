"""False-positive/confidence scorer.

config/prompts.py already states the repro/confidence rules
(MIN_CONFIDENCE_TO_AUTOCONFIRM, MIN_REPRO_COUNT in config/settings.py) but
nothing enforced them until now. This compares a baseline (benign) response
against one or more trigger-attempt responses and produces a numeric
confidence score plus an auto-confirm eligibility flag, so a finding never
reaches "confirmed" on the strength of a single lucky hit.
"""
import json

from langchain_core.tools import tool
from pydantic import BaseModel

from config.settings import settings


class ResponseSignal(BaseModel):
    status_code: int
    body_length: int
    duration_ms: float
    body_snippet: str = ""


class ConfidenceScore(BaseModel):
    score: int
    reproducible: bool
    attempts_matching: int
    attempts_total: int
    requires_human_review: bool
    rationale: str


def score_confidence(
    baseline: ResponseSignal,
    trigger_attempts: list[ResponseSignal],
) -> ConfidenceScore:
    """Score how confident a candidate finding is, given repeated trigger attempts.

    Never mark a finding confirmed on a single request/response pair.
    attempts_matching counts trigger attempts whose signal is distinct from
    baseline (status change, body-length delta beyond noise, or a timing
    delta for blind/time-based checks). A finding only clears auto-confirm
    if it reproduces at least settings.MIN_REPRO_COUNT times AND scores at
    least settings.MIN_CONFIDENCE_TO_AUTOCONFIRM — anything short of that is
    flagged for human review, never silently dropped.
    """
    matching = 0
    for attempt in trigger_attempts:
        status_changed = attempt.status_code != baseline.status_code
        body_delta = abs(attempt.body_length - baseline.body_length)
        body_changed = baseline.body_length == 0 or body_delta / max(baseline.body_length, 1) > 0.05
        timing_changed = attempt.duration_ms > baseline.duration_ms * 2 + 500  # time-based/blind signal

        if status_changed or body_changed or timing_changed:
            matching += 1

    total = len(trigger_attempts)
    reproducible = total > 0 and matching >= settings.MIN_REPRO_COUNT

    # Score scales with the matching ratio, capped at 10, biased down when
    # there aren't even enough attempts to trust regardless of the ratio.
    ratio = matching / total if total else 0.0
    score = round(ratio * 10)
    if total < settings.MIN_REPRO_COUNT:
        score = min(score, settings.MIN_CONFIDENCE_TO_AUTOCONFIRM - 1)

    requires_review = not (reproducible and score >= settings.MIN_CONFIDENCE_TO_AUTOCONFIRM)

    return ConfidenceScore(
        score=score,
        reproducible=reproducible,
        attempts_matching=matching,
        attempts_total=total,
        requires_human_review=requires_review,
        rationale=(
            f"{matching}/{total} attempts showed a signal distinct from baseline "
            f"(status/body/timing delta). "
            + ("Meets repro + confidence thresholds." if not requires_review
               else "Below MIN_REPRO_COUNT or MIN_CONFIDENCE_TO_AUTOCONFIRM — human review required.")
        ),
    )


@tool
def score_finding_confidence(baseline_json: str, trigger_attempts_json: str) -> dict:
    """Score a candidate finding's confidence from baseline vs. trigger-attempt responses.

    Call this before marking ANY finding confirmed. baseline_json is a single
    ResponseSignal object (status_code, body_length, duration_ms). Repeat the
    trigger request settings.MIN_REPRO_COUNT+ times and pass all attempts as
    trigger_attempts_json (a JSON array of ResponseSignal objects) — scoring
    against just one attempt will always come back requires_human_review=True.
    """
    baseline = ResponseSignal(**json.loads(baseline_json))
    trigger_attempts = [ResponseSignal(**a) for a in json.loads(trigger_attempts_json)]
    return score_confidence(baseline, trigger_attempts).model_dump()
