# Investigation Methodology

General approach I follow when triaging an alert, used consistently across the incidents in this repo.

## 1. Start from the alert, not the conclusion
An alert tells you one thing happened — it rarely tells you the whole story. Treat the alert as the entry point into an investigation, not the investigation itself.

## 2. Reconstruct the timeline before judging impact
Before deciding severity or writing remediation steps, pull every relevant event before and after the alert timestamp across the sources that plausibly connect to it (identity, email, endpoint, network). Attacks are chains — the alert is usually one link, not the first or the last.

## 3. Always check what happened *after* the initial trigger
The most common mistake in triage is stopping at "here's how they got in." A compromised account with no follow-up audit-log review looks resolved but isn't. Second-order actions (mailbox rules, new admin roles, scheduled tasks, lateral connections) are often where the actual objective lives.

## 4. Scope before you close
Check whether the same infrastructure, sender, or technique shows up against other users or hosts before calling an incident contained. A single-victim assumption is the easiest way to miss a wider campaign.

## 5. Separate technical root cause from control gaps
Every incident write-up in this repo distinguishes "what the attacker did" from "what should have stopped it and didn't" (e.g., MFA not enforced on a risky sign-in). The second one is usually more valuable to the organization than the first.

## 6. Write for someone who wasn't in your head
A good incident report lets another analyst (or your future self) understand what happened and why you made each call, without needing to re-run every query you ran.
