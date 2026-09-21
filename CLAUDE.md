# IcebergEBS contributor guide

IcebergEBS assesses Chromium-family extensions. It is a Python 3.14+ FastAPI application using SQLModel with PostgreSQL only; the server-rendered Jinja UI consumes the API.

## Essential invariants

- PostgreSQL is required in development, tests, and production. SQLite is unsupported.
- Dependencies live only in `pyproject.toml`; use `uv`, keep `uv.lock` current, and place runtime imports in `[project.dependencies]` rather than the dev group.
- Preserve strict CSP (`script-src 'self'`): self-host assets, use the vendored Alpine CSP build, and do not introduce inline JavaScript, `on*=` handlers, eval, or a CDN.
- Keep secrets environment-only. Do not log, persist, return, or render credentials.
- Apply explicit RBAC to protected routes. Audit every mutation in the transaction that changes state; commit audit records before external effects.
- Keep webhook/proxy/network changes SSRF-safe, including destination validation at use time and safe error handling.
- Use timezone-aware UTC datetimes (`datetime.now(timezone.utc)`).
- Preserve release and publication safeguards: deployable release images come only from the signed, attested tag-release workflow; do not treat development images as releases.

## Conditional references

Read only the references relevant to the files or operation being changed:

- [Development reference](docs/DEVELOPMENT_REFERENCE.md) retains the detailed project, dependency, CI, security, deployment, versioning, and review procedures formerly kept here.
- [Architecture rule](.claude/rules/architecture.md) for `app/**`, `tests/**`, or `alembic/**` changes.
- [Fetcher rule](.claude/rules/fetchers.md) for `app/fetchers/**` or `app/inspector.py` changes.
- [Frontend rule](.claude/rules/frontend.md) for `static/**` or `app/templates/**` changes.
- [Configuration/startup rule](.claude/rules/config-startup.md) for Docker, Compose, Helm, Makefile, or `.env*` changes.
- [Deployment guide](DEPLOYMENT.md) for a deployment; [release procedure](docs/RELEASING.md) for a release; [repository security guide](docs/REPOSITORY_SECURITY.md) for security policy.

These are explicit conditional references for every harness; do not assume `.claude/rules/` files are loaded automatically.

## Validation and publication

Use the smallest relevant validation described in the linked reference. Major behavior changes need focused regression coverage; database-backed tests require the configured PostgreSQL service. Run broad CI-equivalent or browser/Compose checks only when the changed surface and available resources warrant them. Never commit, publish, deploy, tag, or alter credentials without task authority.
