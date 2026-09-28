# Contributing to Audinexia

Thanks for considering a contribution. This is currently a solo-maintained portfolio/research
project working through a documented industry-readiness roadmap, so process is intentionally
lightweight.

## Before you start

For anything beyond a small fix, please open an issue first describing what you'd like to change
and why. This avoids duplicated work and lets us agree on approach before you invest time —
especially relevant right now since large parts of the codebase (the scanning engine, the
framework content model) are mid-rewrite per the roadmap.

## Development setup

```bash
cd backend
./setup.sh        # or .\setup.ps1 on native Windows
source venv/bin/activate
python app.py
```

See the root `README.md` for full setup details.

## Making a change

1. Fork the repo and create a branch off `main`.
2. Keep changes focused — one logical change per pull request.
3. Follow the existing code style (the codebase does not yet have an enforced linter config; match
   what's already there).
4. There is no automated test suite yet (a known gap, tracked in the roadmap). Until one exists,
   describe in your PR how you manually verified the change — which endpoints/flows you exercised
   and what you confirmed.
5. Every org-scoped database query must filter by `org_id` directly in the query, never
   fetch-then-check — this is the single most security-critical convention in this codebase, and a
   missed filter is a direct cross-tenant data leak. See `rbac.py` for the established pattern.

## Commit messages

Plain, descriptive commit messages explaining *why* a change was made, not just what changed.

## Reporting bugs

Use GitHub issues for functional bugs. **Do not** open a public issue for a security
vulnerability — see `SECURITY.md` for how to report those privately.

## Code of conduct

This project follows the `CODE_OF_CONDUCT.md` in this repository. Please read it before
participating.
