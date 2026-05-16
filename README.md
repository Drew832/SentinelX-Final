# SentinelX

**SentinelX** is an enterprise Vulnerability Intelligence and Active Threat
Hunting platform. It bridges the gap between raw vulnerability data and
executive decision-making by correlating the National Vulnerability Database
(NVD) with CISA's Known Exploited Vulnerabilities (KEV) catalog, EPSS
probability scores, MITRE ATT&CK mappings, and live telemetry from Shodan.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  React + TypeScript + Tailwind  ←→  FastAPI (async) ←→ SQLite/Postgres   │
│      Recharts · Leaflet · jsPDF       APScheduler · Shodan · Claude      │
└──────────────────────────────────────────────────────────────────────────┘
```

## Highlights

- **Continuous NVD ingestion (NVD API v2)** — incremental sync every 10 min using
  `lastModStartDate` / `lastModEndDate` formatted to NIST's exact ISO-8601
  spec, paginated, rate-limited (0.6s without an API key, 0.06s with one),
  and upserted via SQLAlchemy.
- **CISA KEV correlation** — daily cron (00:15 UTC) flips an `is_kev` flag on
  any matching CVE, stores KEV metadata (date added, vendor, vulnerability
  name, required action, due date, ransomware use), and stubs missing CVEs so
  the KEV-only filter never misses a freshly-added 0-day.
- **JWT auth with bcrypt + email OTP** — passwords hashed with bcrypt 4.x
  directly (no passlib), tokens signed with `python-jose`, and accounts
  activated only after a 6-digit one-time code is verified out of band.
- **CVE Explorer** — search, severity filter, CVSS score range, Radix UI
  "CISA KEV Only" switch, KEV rows highlighted with a glowing weaponized
  badge, paginated, sortable.
- **Dashboard** — 14-day publication area chart, severity donut, top-10 vendor
  bar chart, KPI cards, auto-refresh every 60s.
- **Real-time Threat Map** — React-Leaflet world map with custom CSS pulsing
  markers. KEV markers pulse faster and have a larger threat radius. Color
  scales with CVSS severity (red 9+, orange 7–8.9, yellow medium, green low).
- **AI Security Assistant (Anthropic Claude)** — backend pulls relevant CVE
  context from the local database (CVE-ID match, keyword search, KEV
  fallback) and proxies the prompt to the Claude Messages API. Falls back to
  a deterministic local summary when no API key is configured.
- **AI-graded Policy Recommendations** — every CVE-to-policy mapping is
  produced by Claude with an explicit `WHY_THIS_MAPS` justification block
  citing CWE / KEV / exposure evidence, with a deterministic fallback when
  the LLM is unavailable.
- **PDF Briefings** — React-rendered jsPDF "Intelligence Report" with the
  brand gradient header (purple → gold), navy body, severity cards, AI brief,
  and recommendation sections.
- **Sentinel theme** — Tailwind palette (`navy`, `slate`, `gold`) plus
  bespoke pulse / glow animations.

## Repository layout

```
backend/
  app/
    api/         FastAPI routers (auth, cves, telemetry, ai, admin)
    core/        config + security helpers (JWT, bcrypt)
    db/          async SQLAlchemy engine + Base
    models/      User, CVE ORM models
    schemas/     Pydantic v2 schemas
    services/    NVD, CISA KEV, Shodan, AI services
    workers/     APScheduler integration
    main.py      FastAPI app + lifespan + CORS
  requirements.txt
  .env.example
frontend/
  src/
    api/         axios client + endpoint helpers
    components/  layout, auth guard, CVE badges, ThreatMap, report template
    context/     AuthContext (JWT + Guest mode)
    pages/       Login, Register, Dashboard, CveExplorer, ThreatMap, Assistant, Reports
    styles/      Tailwind entrypoint and pulse keyframes
    types/       Strict TypeScript interfaces
    utils/       jsPDF report generator, formatting helpers
  package.json
  vite.config.ts
  tailwind.config.js
```

## Quickstart

### Backend

```bash
cd backend
cp .env.example .env          # then edit secrets
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

On first boot the app:

1. Creates SQLite tables (`./sentinelx.db` by default).
2. Bootstraps the initial admin from `INITIAL_ADMIN_*` env vars.
3. Starts the APScheduler with two jobs:
   - `nvd_ingest` — `IntervalTrigger(minutes=10)`
   - `kev_ingest` — `CronTrigger(hour=0, minute=15)`
4. Exposes Swagger UI at `http://localhost:8000/docs`.

Manual triggers (admin-only):

```bash
curl -X POST http://localhost:8000/api/v1/admin/ingest/nvd?minutes=120 \
  -H "Authorization: Bearer <admin-jwt>"
curl -X POST http://localhost:8000/api/v1/admin/ingest/kev \
  -H "Authorization: Bearer <admin-jwt>"
```

### Frontend

```bash
cd frontend
npm install
npm run dev    # → http://localhost:5173
```

Vite proxies `/api/*` to `http://127.0.0.1:8000`. Override with
`VITE_API_TARGET` or `VITE_API_BASE_URL`.

## Environment variables

See [`backend/.env.example`](backend/.env.example) for the full list. Notable:

| Variable                       | Purpose                                                    |
| ------------------------------ | ---------------------------------------------------------- |
| `SECRET_KEY`                   | JWT signing key                                            |
| `DATABASE_URL`                 | `sqlite+aiosqlite:///…` or `postgresql+asyncpg://…`        |
| `NVD_API_KEY`                  | NIST NVD API key (recommended; lifts ingestion delay)      |
| `SHODAN_API_KEY`               | Required for live telemetry (synthetic fallback otherwise) |
| `ANTHROPIC_API_KEY` / `_MODEL` | Claude assistant + policy recommendations                  |
| `SMTP_*`                       | SMTP relay for the email OTP code                          |
| `INITIAL_ADMIN_*`              | Seeds the bootstrap admin on first run                     |

## API surface (`/api/v1`)

| Method | Path                       | Description                                      |
| ------ | -------------------------- | ------------------------------------------------ |
| POST   | `/auth/register`           | Create user, send OTP                            |
| POST   | `/auth/verify-email`       | Activate account with OTP, return JWT            |
| POST   | `/auth/resend-otp`         | Request a fresh OTP                              |
| POST   | `/auth/login`              | OAuth2 password grant → JWT                      |
| GET    | `/auth/me`                 | Current user                                     |
| GET    | `/cves`                    | Paginated CVEs (filters: `only_kev`, severity…)  |
| GET    | `/cves/stats`              | Severity / vendor / 14-day trend rollups         |
| GET    | `/cves/{id}`               | Full CVE detail                                  |
| GET    | `/telemetry`               | Geo-located threat points (Shodan, 24h cached)   |
| POST   | `/ai/chat`                 | Claude RAG over local CVE database (auth)        |
| POST   | `/policy-ai/recommend`     | Claude policy recommendation per profile CVE     |
| GET    | `/reports/executive`       | Executive report JSON                            |
| GET    | `/reports/download`        | Executive report XLSX/CSV/PDF                    |
| POST   | `/admin/ingest/nvd`        | Force NVD ingest window (admin)                  |
| POST   | `/admin/ingest/kev`        | Force CISA KEV refresh (admin)                   |

## Engineering checks

- Bcrypt passwords: register a user and inspect `users.hashed_password` in the
  DB — the value is a `$2b$12$…` hash, never plaintext. The same bcrypt hash
  is used to store the verification OTP so codes are never stored in plain
  text.
- NIST timestamp formatting: `services/nvd_service.format_nvd_timestamp` emits
  `YYYY-MM-DDTHH:MM:SS.000+00:00` exactly as required by NVD API v2.
- Rate limiting: `_request_delay()` returns 0.6s without an API key and 0.06s
  with one. 429 responses trigger a 30s backoff and retry.
- Upsert: `services/nvd_service.upsert_cve` updates the existing row or inserts
  a new one based on the primary `cve_id`.
- KEV pulse intensity: in `frontend/src/components/map/ThreatMap.tsx`,
  `is_kev` flips marker size from 14px → 22px and swaps the pulse animation
  to `kevPulse` (1.1s, scale 3.6) vs `radarPulse` (2s, scale 2.6).

## License

Internal / demonstration use.
