# Security Policy

Audinexia is a policy-compliance and GRC platform, which means the data it holds (organizations'
security posture, unresolved findings, risk registers) is itself sensitive. We take vulnerability
reports seriously and would rather hear about a problem early than have it found for us.

## Current status: pre-GA

Audinexia is an actively-developed portfolio/research project working through a documented
industry-readiness roadmap (see `CHANGELOG.md` and the project's commit history for what's
actually landed). It is **not yet suitable for production use with real sensitive data**.
Specific known limitations, tracked openly rather than hidden:

- No third-party penetration test has been performed yet.
- The Content-Security-Policy is deliberately NOT strict: `script-src` still allows
  `'unsafe-inline'`, because `dashboard.html` has ~50 inline `onclick` handlers that a strict policy
  would break, and migrating them to external event listeners is a separate, regression-prone
  refactor that hasn't been done. The XSS defenses that actually carry the weight today are output
  escaping (every user-originated value in `dashboard.html`'s templates goes through `esc()`, and
  the HTML/PDF report generators escape their output) and httpOnly auth cookies. The escaping was
  a manual sweep and verified by injecting payloads through every UI surface that renders user
  text, but there's no automated test enforcing it — a future template that interpolates raw user
  text would reintroduce the hole.
- The dashboard UI has no screens for the request/approve workflows added to the API (risk
  acceptance, finding closure, reopening or withdrawing an audit). The API enforces them; the UI
  just surfaces the server's error message if you try to set a restricted status directly.
- Password-reset tokens are generated and validated correctly, but the reset link is currently
  logged server-side rather than emailed, since no transactional email provider is configured in
  this environment. Do not rely on this flow for a real account you can't otherwise recover.
- No automated test suite exists yet. Changes are verified manually and the verification steps are
  documented in each change's commit message, but this is a weaker safety net than a real CI suite.

## Reporting a vulnerability

Please report security issues privately rather than opening a public GitHub issue.

- **Email:** lalitbist.edu@gmail.com (subject line: `SECURITY: <short description>`)
- **What to include:** the affected version/commit, steps to reproduce, and the impact you'd
  expect (e.g. "a member-role user can read another organization's findings").

## Response targets

- **Acknowledgement:** within 3 business days.
- **Initial assessment (confirmed / not a vulnerability / need more info):** within 7 business days.
- **Fix for a confirmed critical or high-severity issue:** within 14 days of confirmation, or a
  documented interim mitigation if a full fix needs longer.

This is a solo-maintained project, so these are best-effort targets, not a contractual SLA. If a
report doesn't get a response in the window above, a follow-up email is welcome.

## Scope

In scope: the Flask backend and the server-rendered dashboard UI in this repository.

Out of scope: findings that require an already-compromised admin account to exploit further, or
that rely solely on physical access to the server. Denial-of-service reports without a
resource-exhaustion mechanism (e.g. "the login page is slow") are not actionable without more
detail.

## Disclosure

We ask for a reasonable window to fix a confirmed issue before any public disclosure. There is no
bug bounty program at this time.
