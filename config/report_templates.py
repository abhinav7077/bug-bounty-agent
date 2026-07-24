"""Jinja2 Markdown report templates for skills/report_generator.py — Phase 8.

Three platform-specific section-naming/ordering conventions, kept as string
constants here rather than separate template files, mirroring this file's
own config/prompts.py precedent (prompt TEXT lives as constants, not a
templating language, but the same "config/ holds content, skills/ holds
logic" split applies). Each is a best-effort STRUCTURAL approximation of
that platform's commonly-documented submission format (section names/order
each program's own template guidance describes) — not a literal scrape of
any program's live, possibly-custom submission form, which this project has
no access to and shouldn't pretend to. A human reviews and edits the
rendered output before submitting either way (docs/DEVELOPMENT_PLAN.md's own
Phase 8 "Human review + edit step... before export" line), so a structural
approximation is the right level of fidelity here, not a blocker.

All three render from the SAME context shape (see
skills/report_generator.py's render_report()): target, generated_date,
executive_summary, impact, findings (each with type/target/detail/severity/
tool_source/cvss/remediation/poc/bugcrowd_priority).
"""

HACKERONE_TEMPLATE = """\
# {{ target }} — Security Report

**Report Date:** {{ generated_date }}

## Summary

{{ executive_summary }}

## Impact

{{ impact }}
{% for f in findings %}
## Finding {{ loop.index }}: {{ f.type }} ({{ f.severity | upper }})

**Asset:** `{{ f.target }}`
**CVSS 3.1:** {{ f.cvss.score }} ({{ f.cvss.severity }}) — `{{ f.cvss.vector }}`

{{ f.cvss.justification }}

### Details

{{ f.detail }}

### Steps To Reproduce
{% for step in f.poc.steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
**Request:**
```
{{ f.poc.curl_command }}
```
{% if f.poc.code %}
**Proof of Concept:**
```
{{ f.poc.code }}
```
{% endif %}
### Remediation

{{ f.remediation }}
{% endfor %}
## Disclosure

Submitted via HackerOne. Please acknowledge receipt per your program's stated SLA, and treat
this report and its contents as confidential until a fix is deployed and disclosure is agreed.
"""

BUGCROWD_TEMPLATE = """\
# {{ target }} — Vulnerability Submission

**Date:** {{ generated_date }}

## Description

{{ executive_summary }}

## Business Impact

{{ impact }}
{% for f in findings %}
## Finding {{ loop.index }}: {{ f.type }}

**Target:** `{{ f.target }}`
**Priority:** P{{ f.bugcrowd_priority }} — **CVSS 3.1:** {{ f.cvss.score }} ({{ f.cvss.severity }}) — `{{ f.cvss.vector }}`

{{ f.cvss.justification }}

### Technical Details

{{ f.detail }}

### Steps to Reproduce
{% for step in f.poc.steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
### Proof of Concept

```
{{ f.poc.curl_command }}
```
{% if f.poc.code %}
```
{{ f.poc.code }}
```
{% endif %}
### Suggested Fix

{{ f.remediation }}
{% endfor %}
## Disclosure

Submitted via Bugcrowd. Coordinated disclosure only — please confirm remediation timeline
before any public write-up.
"""

IMMUNEFI_TEMPLATE = """\
# {{ target }} — Bug Report

**Date:** {{ generated_date }}

## Description

{{ executive_summary }}

## Impact

{{ impact }}
{% for f in findings %}
## Finding {{ loop.index }}: {{ f.type }}

**Asset:** `{{ f.target }}`
**Risk Rating:** {{ f.cvss.severity }} (CVSS 3.1: {{ f.cvss.score }} — `{{ f.cvss.vector }}`)

{{ f.cvss.justification }}

### Details

{{ f.detail }}

### Proof of Concept
{% for step in f.poc.steps %}
{{ loop.index }}. {{ step }}
{% endfor %}
```
{{ f.poc.curl_command }}
```
{% if f.poc.code %}
```
{{ f.poc.code }}
```
{% endif %}
### Recommendation

{{ f.remediation }}
{% endfor %}
## Disclosure

Submitted via Immunefi. Please confirm scope/asset ownership and the applicable reward tier
before remediation work begins.
"""

TEMPLATES_BY_PLATFORM = {
    "hackerone": HACKERONE_TEMPLATE,
    "bugcrowd": BUGCROWD_TEMPLATE,
    "immunefi": IMMUNEFI_TEMPLATE,
}
