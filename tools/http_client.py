"""Shared direct-HTTP primitive for skills that speak HTTP themselves rather
than shelling out to a CLI binary.

tools/base.py's run_tool() covers every wrapper around an external tool
binary. This covers the other case: custom request/response logic with no
single CLI tool behind it at all — differential-auth checks, forged-token
replay, response diffing (see skills/auth_mapper.py, the first caller).

Paced to ORCHESTRATOR_SYSTEM_PROMPT rule 4 (max settings.MAX_REQ_PER_SEC),
the same rule run_httpx already enforces via its own -rate-limit flag —
this is that rule applied at the raw-HTTP level for callers that have no
CLI flag to pass it through.

Pacing state is a plain module-level float in a one-item list, deliberately
NOT an asyncio.Lock/Semaphore: agent/graph.py's node_execute runs every tool
via asyncio.run(tool.ainvoke(...)) (see run_tool()'s own docstring), so each
top-level action gets a brand-new event loop. An asyncio.Lock created once at
import time binds to the first loop and raises on the next asyncio.run()
call; a plain float has no event-loop affinity and survives across calls.
"""
import asyncio
import time

import aiohttp
from pydantic import BaseModel

from config.settings import settings

DEFAULT_TIMEOUT_S = 15
_last_request_at = [0.0]


class HttpResponse(BaseModel):
    status: int
    headers: dict[str, str] = {}
    body: str = ""
    elapsed_ms: float = 0.0
    error: str | None = None


async def _pace() -> None:
    min_interval = 1.0 / settings.MAX_REQ_PER_SEC
    wait = _last_request_at[0] + min_interval - time.monotonic()
    if wait > 0:
        await asyncio.sleep(wait)
    _last_request_at[0] = time.monotonic()


async def send_request(
    method: str, url: str, headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None, data: str | None = None,
    timeout_s: int = DEFAULT_TIMEOUT_S, verify_tls: bool = True,
) -> HttpResponse:
    """Send one real HTTP request. Paced, never raises — same contract as run_tool().

    This function has no opinion on risk level: it sends whatever it's told
    to send. Every skill/tool that calls it — especially anything that
    forges, tampers with, or replays auth material — must still get its own
    explicit entry in agent/risk.py, classified by what THAT caller does,
    not by anything in here.
    """
    await _pace()
    start = time.monotonic()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method, url, headers=headers, params=params, data=data,
                timeout=aiohttp.ClientTimeout(total=timeout_s),
                ssl=None if verify_tls else False,
                allow_redirects=False,
            ) as resp:
                body = await resp.text(errors="replace")
                return HttpResponse(
                    status=resp.status,
                    headers=dict(resp.headers),
                    body=body,
                    elapsed_ms=(time.monotonic() - start) * 1000,
                )
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        return HttpResponse(
            status=0, elapsed_ms=(time.monotonic() - start) * 1000,
            error=f"{method} {url} failed: {exc}",
        )
