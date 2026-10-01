---
name: ScamCheck phone-risk semantics
description: ScamCheck's local phone-list match rule and safeguards around unverified reports.
---

A match in either local phone list is an app-specific `HIGH RISK — THREAT DETECTED` result, regardless of whether the entry is verified or user-submitted.

**Why:** The user explicitly chose list membership as the app's risk criterion without requiring additional proof.

**How to apply:** Keep user-submitted and unverified provenance clear; do not claim to know who owns a number or that a specific person committed a crime. An unmatched number should be labeled `Not found in our list`, and absence is not evidence of safety.