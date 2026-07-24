"""WAF / filter bypass variant generator.

Called when a payload gets blocked. Generates encoding, case-mutation, and
structural variants to retry — it does not send anything itself, the caller
still routes each variant back through the normal HITL-gated tool path.
"""
from langchain_core.tools import tool


def _url_encode_angles(s: str) -> str:
    return s.replace("<", "%3C").replace(">", "%3E")


def _hex_encode_angles(s: str) -> str:
    return s.replace("<", "\\x3c").replace(">", "\\x3e")


def _case_mutate_tags(s: str) -> str:
    out = []
    tag_chars = 0
    in_tag = False
    for ch in s:
        if ch == "<":
            in_tag = True
        if in_tag and ch.isalpha():
            out.append(ch.upper() if tag_chars % 2 == 0 else ch.lower())
            tag_chars += 1
        else:
            out.append(ch)
        if ch == ">":
            in_tag = False
    return "".join(out)


_TRANSFORMS = [
    _url_encode_angles,
    _hex_encode_angles,
    _case_mutate_tags,
    lambda s: s.replace("<script>", "<script\x0d>"),          # CR injection
    lambda s: s.replace("<script>", "<!--><script>"),         # comment break
    lambda s: s.replace(" ", "/**/"),                         # SQLi comment spacing
    lambda s: s.replace(" ", "+"),                             # plus encoding
    lambda s: s + "<!--",                                       # comment suffix
    lambda s: s.replace("=", "%3D"),                            # encode assignment
]


@tool
def get_waf_bypasses(blocked_payload: str, waf_signature: str = "unknown") -> list[str]:
    """Generate bypass variants for a payload that was blocked by a WAF/filter.

    Call this whenever a scan or fuzz attempt comes back blocked/filtered
    (403, WAF challenge page, sanitized reflection, etc). Each variant is a
    candidate to retry through the normal tool path — this function never
    sends a request itself.
    """
    variants = {transform(blocked_payload) for transform in _TRANSFORMS}
    variants.discard(blocked_payload)

    # HTTP-method-switch and chunked-encoding bypasses aren't string
    # transforms of the payload — surface them as instructions instead.
    method_hints = [
        "retry as PUT/PATCH/TRACE instead of GET/POST",
        "retry with Transfer-Encoding: chunked",
        "retry with an extra trailing '?' or ';' on the request path",
    ]
    return sorted(variants) + method_hints
