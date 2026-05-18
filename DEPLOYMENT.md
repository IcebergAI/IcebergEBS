# Marvin — Containerised Deployment (PostgreSQL + Nginx)

## Context

Marvin currently runs on SQLite with no reverse proxy. This plan replaces SQLite with PostgreSQL and adds nginx as a TLS-terminating reverse proxy following security hardening best practices. Everything is wired together with Docker Compose for a one-command production deployment.

---

## Files to create

| Path | Purpose |
|------|---------|
| `Dockerfile` | App image |
| `docker-compose.yml` | Three-service stack (postgres, app, nginx) |
| `.dockerignore` | Exclude secrets, venv, DB files |
| `.env.example` | Template for required env vars |
| `nginx/nginx.conf` | Full nginx config |
| `nginx/security_headers.conf` | Shared header include (avoids duplication across location blocks) |
| `nginx/generate-dev-cert.sh` | One-shot self-signed cert for local dev |
| `static/js/tailwind-config.js` | Move inline Tailwind config out of HTML (required for CSP) |

## Files to modify

| Path | Change |
|------|--------|
| `requirements.txt` | Add `asyncpg`; keep `aiosqlite` (still used by tests) |
| `app/database.py` | Conditional WAL pragma (SQLite only); add Postgres pool settings |
| `app/templates/base.html` | Replace inline `tailwind.config` script with `<script src="/static/js/tailwind-config.js">` |

---

## 1. `requirements.txt`

Add `asyncpg` after `aiosqlite`. Both stay — `aiosqlite` is still used by the in-memory SQLite fixtures in `tests/conftest.py`.

---

## 2. `app/database.py`

Two changes:

**a) Conditional WAL pragma** — `PRAGMA journal_mode=WAL` is SQLite-only; calling it against Postgres raises an error:

```python
async def init_db() -> None:
    async with engine.begin() as conn:
        if settings.database_url.startswith("sqlite"):
            await conn.execute(text("PRAGMA journal_mode=WAL"))
        await conn.run_sync(SQLModel.metadata.create_all)
```

**b) Postgres connection pool** — SQLAlchemy's default pool is too small for production; SQLite uses `StaticPool` and must not be given pool kwargs:

```python
_is_sqlite = settings.database_url.startswith("sqlite")
_pool_kwargs = {} if _is_sqlite else {
    "pool_size": 5,
    "max_overflow": 10,
    "pool_pre_ping": True,
    "pool_timeout": 30,
}
engine: AsyncEngine = create_async_engine(settings.database_url, echo=False, **_pool_kwargs)
```

---

## 3. `app/templates/base.html` + `static/js/tailwind-config.js`

The existing inline `tailwind.config = {...}` block (lines 16–25 of `base.html`) cannot be hash-allowed in a CSP without tracking the hash across every edit. Move it to a static file:

**`static/js/tailwind-config.js`**:
```js
tailwind.config = {
  theme: { extend: {
    fontFamily: {
      sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
      mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
    },
  } },
};
```

**`base.html`**: Replace the inline `<script>…tailwind.config…</script>` block with:
```html
<script src="/static/js/tailwind-config.js"></script>
```

The anti-flash inline script (line 7) cannot be moved — it must execute before first paint to prevent a theme flash. It is allowed in the CSP via a static SHA-256 hash computed during implementation:
```
sha256-<hash-of-exact-script-bytes>
```

---

## 4. `Dockerfile`

```dockerfile
FROM python:3.14-slim

WORKDIR /app

RUN adduser --disabled-password --gecos '' appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R appuser:appuser /app
USER appuser

CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips=*"]
```

Notes:
- `--proxy-headers` makes uvicorn trust `X-Forwarded-For` / `X-Forwarded-Proto` from nginx
- Single worker only — APScheduler runs per-process; multiple workers would each schedule independent watchlist refreshes, causing duplicate fetches and duplicate `AlertLog` entries

---

## 5. `.dockerignore`

```
.env
*.db
venv/
__pycache__/
.git/
tests/
*.pyc
nginx/certs/
```

---

## 6. `docker-compose.yml`

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: ${POSTGRES_DB:-marvin}
      POSTGRES_USER: ${POSTGRES_USER:-marvin}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-marvin} -d ${POSTGRES_DB:-marvin}"]
      interval: 5s
      timeout: 5s
      retries: 10
    restart: unless-stopped

  app:
    build: .
    environment:
      MARVIN_DATABASE_URL: postgresql+asyncpg://${POSTGRES_USER:-marvin}:${POSTGRES_PASSWORD}@postgres/${POSTGRES_DB:-marvin}
      MARVIN_ADMIN_USERNAME: ${MARVIN_ADMIN_USERNAME}
      MARVIN_ADMIN_PASSWORD: ${MARVIN_ADMIN_PASSWORD}
      MARVIN_SECRET_KEY: ${MARVIN_SECRET_KEY}
      MARVIN_APP_BASE_URL: ${MARVIN_APP_BASE_URL:-}
      MARVIN_SECURE_COOKIES: "true"
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/security_headers.conf:/etc/nginx/security_headers.conf:ro
      - ./nginx/certs:/etc/nginx/certs:ro
      - ./static:/app/static:ro
    depends_on:
      - app
    restart: unless-stopped

volumes:
  postgres_data:
```

---

## 7. `.env.example`

```env
# PostgreSQL
POSTGRES_DB=marvin
POSTGRES_USER=marvin
POSTGRES_PASSWORD=<generate: openssl rand -hex 32>

# Marvin app
MARVIN_ADMIN_USERNAME=admin
MARVIN_ADMIN_PASSWORD=<strong password>
MARVIN_SECRET_KEY=<generate: python -c "import secrets; print(secrets.token_hex(32))">
MARVIN_APP_BASE_URL=https://your-domain.example.com
```

---

## 8. `nginx/generate-dev-cert.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "$(dirname "$0")/certs"
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout "$(dirname "$0")/certs/key.pem" \
  -out    "$(dirname "$0")/certs/cert.pem" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
echo "Self-signed cert written to nginx/certs/. For production, replace with a real cert."
```

For production: mount a Let's Encrypt cert (e.g. via Certbot) or any CA-issued cert+key at `nginx/certs/cert.pem` and `nginx/certs/key.pem`.

---

## 9. `nginx/security_headers.conf`

Extracted so that every `location` block can `include` it without repetition. (Nginx drops parent-block `add_header` directives the moment a child location block defines any `add_header` of its own — the include pattern is the standard workaround.)

```nginx
# Compute the SHA-256 of the anti-flash inline script during implementation
# and substitute <HASH> below.
add_header Content-Security-Policy
  "default-src 'self'; \
   script-src 'self' 'sha256-<HASH>' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; \
   style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
   font-src 'self' https://fonts.gstatic.com; \
   img-src 'self' data:; \
   connect-src 'self'; \
   frame-ancestors 'none'; \
   base-uri 'self'; \
   form-action 'self'" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "same-origin" always;
add_header Permissions-Policy
  "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" always;
```

Note on `style-src 'unsafe-inline'`: Tailwind CDN injects styles at runtime via a `<style>` tag; this directive is unavoidable with the CDN build. To eliminate it entirely, switch to the Tailwind CLI build process (a future hardening step, not in scope here).

---

## 10. `nginx/nginx.conf`

```nginx
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    server_tokens off;  # Don't expose nginx version in headers or error pages

    log_format main '$remote_addr - [$time_local] "$request" $status $body_bytes_sent';
    access_log /var/log/nginx/access.log main;

    sendfile        on;
    tcp_nopush      on;
    keepalive_timeout 65;

    gzip            on;
    gzip_vary       on;
    gzip_types      text/plain text/css application/json application/javascript text/javascript;

    client_max_body_size 2m;

    # Rate-limit zones
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
    limit_req_zone $binary_remote_addr zone=api:10m   rate=60r/m;

    # HTTP -> HTTPS redirect
    server {
        listen 80;
        server_name _;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl;
        http2 on;
        server_name _;

        ssl_certificate     /etc/nginx/certs/cert.pem;
        ssl_certificate_key /etc/nginx/certs/key.pem;

        # Modern TLS: 1.2 minimum, 1.3 preferred
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256;
        ssl_prefer_server_ciphers off;

        ssl_session_cache   shared:SSL:10m;
        ssl_session_timeout 1d;
        ssl_session_tickets off;

        # Uncomment for production CA-issued certs only (not self-signed):
        # ssl_stapling on;
        # ssl_stapling_verify on;

        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 10s;
        proxy_send_timeout    10s;
        proxy_read_timeout    120s;

        # Static assets served directly by nginx
        location /static/ {
            alias /app/static/;
            expires 1y;
            include /etc/nginx/security_headers.conf;
            add_header Cache-Control "public, immutable" always;
        }

        # Login — tight rate limit
        location = /login {
            limit_req zone=login burst=5 nodelay;
            include /etc/nginx/security_headers.conf;
            proxy_pass http://app:8000;
        }

        # API — moderate rate limit
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            include /etc/nginx/security_headers.conf;
            proxy_pass http://app:8000;
        }

        location / {
            include /etc/nginx/security_headers.conf;
            proxy_pass http://app:8000;
        }
    }
}
```

---

## Inline script hash

During implementation, compute the SHA-256 of the anti-flash script (the exact bytes between the `<script>` tags on line 7 of `base.html`):

```bash
printf '%s' "(function(){var t=localStorage.getItem('marvin-theme')||'light';document.documentElement.setAttribute('data-theme',t);})()" \
  | openssl dgst -sha256 -binary | openssl base64
```

Substitute the result as `'sha256-<base64>'` in `security_headers.conf`. This is the only inline script remaining after the `tailwind-config.js` extraction.

---

## Build order

1. `requirements.txt` — add `asyncpg`
2. `app/database.py` — conditional WAL + pool settings
3. `static/js/tailwind-config.js` — new file
4. `app/templates/base.html` — replace inline script block with `<script src>` tag
5. `Dockerfile`, `.dockerignore`, `.env.example`
6. `docker-compose.yml`
7. `nginx/generate-dev-cert.sh`
8. Compute inline script SHA-256 hash
9. `nginx/security_headers.conf` — with computed hash
10. `nginx/nginx.conf`

---

## Verification

```bash
# Generate dev cert
bash nginx/generate-dev-cert.sh

# Copy and fill in env vars
cp .env.example .env && $EDITOR .env

# Build and start
docker compose up --build

# Check TLS and headers
curl -sko /dev/null -D - https://localhost/ | grep -E "HTTP|Content-Security|Strict-Transport|X-Frame|X-Content"

# HTTP -> HTTPS redirect
curl -sI http://localhost/ | head -3

# Static asset served by nginx (not proxied through Python)
curl -sI https://localhost/static/css/app.css | grep -E "Cache-Control|Server"

# Tests still pass (in-memory SQLite, unaffected by Postgres changes)
venv/bin/python -m pytest tests/ -v
```

For production: replace `nginx/certs/` with a real certificate, uncomment OCSP stapling, and set `MARVIN_APP_BASE_URL` to your public domain.

---

# Option B — Kubernetes (Helm chart)

Assumes the cluster already has:
- **nginx-ingress-controller** (`ingress-nginx`)
- **cert-manager** with a `ClusterIssuer` named `letsencrypt-prod`

PostgreSQL is deployed as a Bitnami subchart — no separate StatefulSet to maintain.

## Helm chart layout

```
helm/marvin/
├── Chart.yaml
├── values.yaml
└── templates/
    ├── _helpers.tpl
    ├── deployment.yaml
    ├── service.yaml
    ├── ingress.yaml
    ├── configmap.yaml
    └── secret.yaml
```

---

## `helm/marvin/Chart.yaml`

```yaml
apiVersion: v2
name: marvin
description: Extension risk monitor
type: application
version: 0.1.0
appVersion: "1.0.0"
dependencies:
  - name: postgresql
    version: "~15.x.x"
    repository: https://charts.bitnami.com/bitnami
```

---

## `helm/marvin/values.yaml`

```yaml
image:
  repository: ghcr.io/yourorg/marvin   # or local registry
  tag: latest
  pullPolicy: IfNotPresent

# Must stay at 1 — APScheduler runs per-process; multiple replicas would
# each independently refresh watchlisted extensions and write duplicate AlertLog rows.
replicaCount: 1

marvin:
  adminUsername: admin
  adminPassword: ""        # override with --set or existingSecret
  secretKey: ""            # override with --set or existingSecret
  appBaseUrl: ""           # e.g. https://marvin.example.com
  fetchIntervalMinutes: 60
  secureCookies: true

postgresql:
  auth:
    username: marvin
    password: ""           # override with --set or existingSecret
    database: marvin

ingress:
  host: marvin.example.com
  className: nginx
  certManagerIssuer: letsencrypt-prod  # set "" to disable cert-manager annotation

resources:
  requests:
    cpu: 100m
    memory: 256Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

**Never commit passwords in `values.yaml`.** Use `--set` for ad-hoc installs or a `SealedSecret` / ExternalSecret for GitOps.

---

## `helm/marvin/templates/secret.yaml`

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: {{ include "marvin.fullname" . }}
type: Opaque
stringData:
  admin-password: {{ .Values.marvin.adminPassword | required "marvin.adminPassword is required" | quote }}
  secret-key:     {{ .Values.marvin.secretKey     | required "marvin.secretKey is required"     | quote }}
```

---

## `helm/marvin/templates/configmap.yaml`

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "marvin.fullname" . }}
data:
  MARVIN_ADMIN_USERNAME:        {{ .Values.marvin.adminUsername | quote }}
  MARVIN_APP_BASE_URL:          {{ .Values.marvin.appBaseUrl | quote }}
  MARVIN_FETCH_INTERVAL_MINUTES: {{ .Values.marvin.fetchIntervalMinutes | quote }}
  MARVIN_SECURE_COOKIES:        {{ .Values.marvin.secureCookies | quote }}
```

---

## `helm/marvin/templates/deployment.yaml`

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "marvin.fullname" . }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      app.kubernetes.io/name: {{ include "marvin.name" . }}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: {{ include "marvin.name" . }}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: marvin
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - containerPort: 8000
          envFrom:
            - configMapRef:
                name: {{ include "marvin.fullname" . }}
          env:
            - name: MARVIN_DATABASE_URL
              value: "postgresql+asyncpg://{{ .Values.postgresql.auth.username }}:$(POSTGRES_PASSWORD)@{{ include \"marvin.fullname\" . }}-postgresql/{{ .Values.postgresql.auth.database }}"
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: {{ include "marvin.fullname" . }}-postgresql
                  key: password
            - name: MARVIN_ADMIN_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: {{ include "marvin.fullname" . }}
                  key: admin-password
            - name: MARVIN_SECRET_KEY
              valueFrom:
                secretKeyRef:
                  name: {{ include "marvin.fullname" . }}
                  key: secret-key
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: [ALL]
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
          readinessProbe:
            httpGet:
              path: /login
              port: 8000
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /login
              port: 8000
            initialDelaySeconds: 15
            periodSeconds: 30
```

Note: `readOnlyRootFilesystem: true` is desirable but requires a writable `/tmp` emptyDir mount because Python and uvicorn write bytecode cache and socket files. Add if needed:
```yaml
volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

---

## `helm/marvin/templates/service.yaml`

```yaml
apiVersion: v1
kind: Service
metadata:
  name: {{ include "marvin.fullname" . }}
spec:
  type: ClusterIP
  ports:
    - port: 8000
      targetPort: 8000
  selector:
    app.kubernetes.io/name: {{ include "marvin.name" . }}
```

---

## `helm/marvin/templates/ingress.yaml`

Security headers are applied via the `configuration-snippet` annotation. This is the nginx-ingress equivalent of the `security_headers.conf` include in the Docker Compose setup.

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "marvin.fullname" . }}
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "2m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "120"
    nginx.ingress.kubernetes.io/limit-rps: "2"
    nginx.ingress.kubernetes.io/limit-connections: "20"
    nginx.ingress.kubernetes.io/configuration-snippet: |
      add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'sha256-<HASH>' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;
      add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" always;
    {{- if .Values.ingress.certManagerIssuer }}
    cert-manager.io/cluster-issuer: {{ .Values.ingress.certManagerIssuer | quote }}
    {{- end }}
spec:
  ingressClassName: {{ .Values.ingress.className }}
  tls:
    - hosts:
        - {{ .Values.ingress.host }}
      secretName: {{ include "marvin.fullname" . }}-tls
  rules:
    - host: {{ .Values.ingress.host }}
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: {{ include "marvin.fullname" . }}
                port:
                  number: 8000
```

`HSTS`, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` are set automatically by nginx-ingress when `ssl-redirect` is enabled; the snippet adds the headers that ingress-nginx does not set by default (CSP and Permissions-Policy). Verify with `curl -sI https://your-host/ | grep -i -E "content-security|permissions"`.

---

## Installing

```bash
# Add Bitnami repo and update deps
helm repo add bitnami https://charts.bitnami.com/bitnami
helm dependency update helm/marvin

# Install (generate strong values; never commit these)
helm upgrade --install marvin helm/marvin \
  --namespace marvin --create-namespace \
  --set marvin.adminPassword="$(openssl rand -hex 16)" \
  --set marvin.secretKey="$(openssl rand -hex 32)" \
  --set postgresql.auth.password="$(openssl rand -hex 32)" \
  --set marvin.appBaseUrl="https://marvin.example.com" \
  --set ingress.host="marvin.example.com"

# Watch rollout
kubectl rollout status deployment/marvin -n marvin
```

For GitOps (Flux / ArgoCD): use `SealedSecret` or an ExternalSecrets `ExternalSecret` object to inject passwords from your secrets store rather than `--set`.

---

## Comparison: Docker Compose vs Kubernetes

| Concern | Docker Compose | Kubernetes (Helm) |
|---------|---------------|-------------------|
| Complexity | Low | Medium |
| TLS | Manual cert or self-signed | cert-manager + Let's Encrypt (automatic) |
| Scaling | Single host | Multi-node |
| Secret management | `.env` file | K8s Secret / ExternalSecret |
| PostgreSQL | Docker volume | Bitnami subchart (StatefulSet) |
| Upgrades | `docker compose pull && up` | `helm upgrade` |
| Best for | Single-server / homelab | Cloud / team deployments |
