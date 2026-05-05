# Marvin - Paranoid about Chrome extensions

## Summary
Collect information about extensions for chromium type apps, Chrome, Edge, VSCode etc. and provide risk scoring. Signals that maybe considered are ownership change, popularity, permissions requested etc 

## Environment, Frameworks and Libraries
App will always run on Python 3.14 or later.

### Python
- FastAPI
- SQLModel (with aiosqlite for async SQLite)
- HTTPX
- pytest + pytest-asyncio
- pydantic-settings (config from env vars)
- itsdangerous (session cookie signing)
- jinja2 + python-multipart (templates + form parsing)
- uvicorn[standard] (ASGI server)

### UI / Front end
- AlpineJS (via CDN)
- Tailwind CSS (via CDN in dev; build output at `static/css/app.css`)
- JetBrains Mono (Google Fonts)
- Gruvbox dark colour palette (CSS custom properties in `static/css/app.css`)


## Architecture
API-first design. All data flows through FastAPI endpoints; the UI consumes them. HTML routes render Jinja2 templates; API routes return JSON.

## Testing

Ensure tests are added for major functionality changes and regression tests are added where bugs are identified.

### Running Tests
```bash
venv/bin/python -m pytest tests/ -v
```

`pytest.ini` sets `asyncio_mode = auto` so async tests run without extra decoration.


## Maintenance
- Keep this file up to date with decisions around structure, architecture, and function.
- Ensure README.md is up to date and accurate.
- Ensure the application's help page is up to date and accurate.

## Security
- Security of the application is a priority.
- Validate code to ensure there are no serious security flaws.
- Ensure authentication is applied to endpoints that shouldn't be public.
- Use `hmac.compare_digest` for all password comparisons (timing-safe).
- Jinja2 autoescaping is on by default — do not disable it.

## Styling, Theming and Design
Retro/terminal feel using the Gruvbox dark colour scheme.