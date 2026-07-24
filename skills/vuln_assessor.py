"""LLM-based false-positive filter + confidence scorer for a batch of findings.

Closes docs/DEVELOPMENT_PLAN.md's Phase 5 "LLM vuln assessor: reads raw
scanner output -> filters likely false positives -> assigns confidence
score" item.

Distinct from skills/confidence_scorer.py's score_finding_confidence:
that tool scores ONE finding from repeated baseline-vs-trigger
ResponseSignal pairs (a statistical signal from N actual repeated requests) —
built for a caller that can afford to replay a single check multiple times.
Scanner output accumulated across a pipeline (nuclei matches, introspection
results, port/service findings, ...) has no such repeated-attempt data
sitting around per finding, and re-running every single one N times before
triage would multiply request volume for little benefit at pure-recon-level
severity. This assesses a whole BATCH in one LLM pass instead, using the
finding's own text (type/detail/severity/tool_source) as its only signal —
a coarser, cheaper first triage pass, not a replacement for
score_finding_confidence on any individual finding a human decides is worth
the repeated-request cost to confirm further.
"""
import json

from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from pydantic import BaseModel

from config.settings import settings

_llm = ChatOllama(
    base_url=settings.OLLAMA_BASE_URL,
    model=settings.OLLAMA_MODEL,
    temperature=settings.LLM_TEMPERATURE,
    num_ctx=settings.OLLAMA_NUM_CTX,
)

_ASSESS_PROMPT_TEMPLATE = """You are a false-positive triage analyst for a bug bounty hunt.
Given this numbered list of raw scanner findings, assess each one for how likely it is to be a \
real, exploitable issue versus scanner noise (a generic banner match, a template matching a \
default/benign page, a low-signal informational fingerprint, etc).

For each finding, consider:
- Does the detail describe a specific, concrete signal (a real matched pattern, a distinct \
status/body change) or just a generic template/category name with no real evidence shown?
- Does the tool_source/type combination have a history of noisy matches (e.g. broad nuclei \
tech-detection tags, generic misconfig templates) versus a targeted, purpose-built check?
- Severity alone is not confidence — a "critical"-labeled finding with weak evidence should
  still score low confidence, and a "low"-labeled finding with strong evidence can score high.

FINDINGS (0-indexed):
{findings_json}

Return ONLY a JSON array, same length and order as the input, no prose, in this shape:
[{{"index": 0, "confidence": 7, "likely_false_positive": false, "rationale": ""}}]
confidence is an integer 0-10. Every input index must appear exactly once in the output.
"""


class FindingAssessment(BaseModel):
    index: int
    confidence: int
    likely_false_positive: bool
    rationale: str


def _condensed_finding(f: dict) -> dict:
    return {
        "type": f.get("type", ""), "target": f.get("target", ""),
        "detail": f.get("detail", "")[:500], "severity": f.get("severity", "info"),
        "tool_source": f.get("tool_source", ""),
    }


@tool
def assess_findings(findings_json: str) -> str:
    """Batch-triage a list of raw Finding dicts for likely false positives and confidence.

    Call this once per scan stage against the findings that stage produced,
    not one finding at a time — a single LLM pass over the whole batch is
    far cheaper than N separate calls and lets the model compare findings
    against each other's evidence quality.

    Input: JSON string, a list of Finding-shaped dicts. Output: JSON string,
    a list of FindingAssessment objects (index/confidence/
    likely_false_positive/rationale), same length and order as the input —
    always returns one entry per input finding, even on a fallback (see
    below), so callers can zip() the two lists without a length mismatch.
    """
    findings = json.loads(findings_json)
    if not findings:
        return "[]"

    condensed = [_condensed_finding(f) for f in findings]
    prompt = _ASSESS_PROMPT_TEMPLATE.format(
        findings_json=json.dumps(list(enumerate(condensed))),
    )
    response = _llm.invoke([HumanMessage(content=prompt)])
    content = response.content.strip()

    fallback = [
        FindingAssessment(
            index=i, confidence=0, likely_false_positive=False,
            rationale="assessment unavailable — model output was malformed, defaulting to human review",
        ).model_dump()
        for i in range(len(findings))
    ]

    try:
        start, end = content.index("["), content.rindex("]") + 1
        parsed = [FindingAssessment(**item).model_dump() for item in json.loads(content[start:end])]
    except (ValueError, TypeError, json.JSONDecodeError):
        return json.dumps(fallback)

    by_index = {item["index"]: item for item in parsed if 0 <= item["index"] < len(findings)}
    return json.dumps([by_index.get(i, fallback[i]) for i in range(len(findings))])
