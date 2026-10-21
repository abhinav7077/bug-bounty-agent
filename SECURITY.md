# Security Policy

## This is a security-testing tool — use it only with authorization

Bug Bounty Agent automates reconnaissance and vulnerability assessment. Running it against
systems you do not own or do not have **explicit written authorization** to test (a bug bounty
program's published scope, a signed penetration-testing engagement, or your own lab) may be
illegal in your jurisdiction and is never condoned by this project.

The tool is built to keep a human in the loop for exactly this reason: every active or risky
action is gated behind an explicit approval, scope cannot be fabricated by the model, and the
risk level of each action is a fixed classification rather than something the LLM self-assigns.
Those are guardrails, not a substitute for your own authorization to test a target. You are
responsible for how you use it.

## Reporting a vulnerability *in this tool*

If you find a security issue **in Bug Bounty Agent itself** (for example, a way for a scanned
target to execute code on the operator's machine, a path traversal in result handling, or a
flaw that weakens the human-approval gate), please report it privately rather than opening a
public issue:

- Open a [GitHub Security Advisory](https://github.com/abhinav7077/bug-bounty-agent/security/advisories/new)
  (preferred — this keeps the report private until a fix is ready), **or**
- Open a regular issue that contains only "I'd like to report a security issue, please get in
  touch" with no exploit details, and the maintainer will arrange a private channel.

Please include, where possible:

- The version or commit you were running.
- A description of the issue and its impact.
- Steps to reproduce, or a minimal proof of concept.

### What to expect

This is a community project maintained on a best-effort basis, so response times are not
guaranteed. The intent is to acknowledge a valid report, work with you on a fix, and credit you
in the release notes unless you prefer to remain anonymous.

## Supported versions

Fixes are applied to the latest `main`. There is no long-term support branch; please test
against the current `main` before reporting.
