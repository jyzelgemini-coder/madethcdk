# ⚡ CDK Gateway

A full-stack **CDK activation gateway** built with **Next.js (App Router) + React + TypeScript** and **SQLite** (`better-sqlite3`).

It has two areas:

| Area | URL | Purpose |
| --- | --- | --- |
| **User site** | `/` and `/guide` | Users enter a CDK key + Gemini account to activate, and track live progress. |
| **Admin panel** | `/admin` | Admin creates CDK keys (one-time use), views stats, and manages key availability. |

---

## ✨ Features

### User site
- **3-step activation flow** — Check code → Account info → Live progress (polls every 5s).
- **Check status** — Look up a CDK code or Task ID to see the latest activation result.
- **Guide page** with step-by-step instructions + embedded YouTube tutorial.
- **Multi-language UI**: **English 🇬🇧 / Khmer 🇰🇭 / Chinese 🇨🇳** (persisted in `localStorage`).
- Dark, tech-style UI (Orbitron + Inter fonts) ported from the original design.

### Admin panel (`/admin`)
- Secure login (PBKDF2 password hashing, httpOnly signed session cookie, login rate-limit).
- **Create CDK keys** — auto-generate (`MD-CDK-` + random 4-letter word + 3-digit number, e.g. `MD-CDK-KRYT238`) or paste your own; set plan.
- **Key table** with status badges (`available` / `used` / `disabled`), used-by email, timestamps.
- **Stats dashboard** (total / available / used / disabled).
- Disable / re-enable keys, delete one key or every key currently shown (type-to-confirm).
- **Activity log** — every redemption with the account used, outcome, failure reason, client IP, device and timestamps; filterable, searchable and exportable to CSV.
- Used keys are locked forever (cannot be re-enabled).

### Backend (API routes)
- `POST /api/v1/cdk/check` — validate a code.
- `POST /api/v1/cdk/activate` — **atomically consume** a key and start a task.
- `GET /api/v1/task/status?task_id=...` — live task progress.
- `POST|DELETE /api/admin/login` — admin auth (with rate limiting).
- `GET|POST|DELETE /api/admin/keys` — list/create keys, bulk delete (admin only).
- `PATCH|DELETE /api/admin/keys/[id]` — enable/disable or delete one key (admin only).
- `GET /api/admin/logs` — paged activation history with filters (admin only).

---

## 🔒 Single-Use Key Guarantee

A CDK key **can only be activated once** and **can never be reused**, enforced at the database level:

1. `claimKey()` runs inside a SQLite transaction:
   ```sql
   UPDATE keys SET status='used', used_at=?, used_by_email=?, task_id=?
   WHERE id=? AND status='available'
   ```
2. If the UPDATE matches **0 rows**, the claim fails and the request is rejected with `409 Conflict`.
3. The claim happens **before** the Pixel job is submitted, so two simultaneous
   requests with the same code can never enqueue two jobs — the loser is
   rejected before any upstream work happens. If the submission is then
   rejected, `releaseKey()` hands the code back so the customer can retry.
4. Codes are unique in the `keys` table (`ON CONFLICT DO NOTHING`), so the same code can never exist twice.
5. The `/cdk/check` endpoint also reports a key as `409` once it is used, so users are warned before entering account info.
6. The admin API refuses to re-enable any key whose status is `used`.

This is **race-safe**: concurrent duplicate activations of the same code cannot both succeed.

---

## 🚀 Getting Started

### Requirements
- Node.js **18.18+** (tested on 22)
- npm

### 1. Install
```bash
npm install
```

### 2. Configure admin (optional but recommended)
Copy the example and change the credentials **before** first login:
```bash
cp .env.example .env.local
# edit ADMIN_USERNAME / ADMIN_PASSWORD / ADMIN_SECRET
```

| Variable | Default | Description |
| --- | --- | --- |
| `ADMIN_USERNAME` | `admin` | Username of the **first** admin (only seeded when the table is empty) |
| `ADMIN_PASSWORD` | `admin123` in dev | Password for that first admin. Leave unset in production: a random one is generated and printed once. Rotate later with `npm run admin:password` |
| `ADMIN_SECRET` | dev fallback | HMAC secret for session cookies. **Required in production** — at least 32 characters and not the example value, or the app refuses to sign sessions |
| `TRUSTED_PROXY_HOPS` | `1` | Reverse proxies in front of the app. The client IP is read this many hops from the right of `X-Forwarded-For`; use `0` when exposed directly |
| `PIXEL_API_KEY` | — | Pixel Partner API v2 key (server-side only) |
| `NEXT_PUBLIC_API_BASE` | `/api/v1` | Optional override for the client API base |

Change the password of an existing admin at any time:

```bash
npm run admin:password                 # generates and prints a strong one
npm run admin:password "my password"   # or set your own (12+ chars)
```

### 3. Run
```bash
# Development
npm run dev        # → http://localhost:3000

# Production
npm run build
npm start          # → http://localhost:3000
```

### 4. First use
1. Open **`http://localhost:3000/admin`** and sign in (default `admin` / `admin123` unless changed).
2. Create some keys (auto-generate or paste).
3. Open the user site, enter a key on the *Activate* page, fill in a Gemini account, and watch the live progress.
4. Try the same key again — it will be rejected. ✅

---

## 🗄️ Data Storage

- SQLite database file: **`data/cdk.db`** (created automatically, WAL mode).
- Tables:
  - `keys` — code, plan, status, used-by, timestamps.
  - `tasks` — task id, code, email, status, progress, message, client IP, user agent (this is the activity log).
  - `admins` — username, PBKDF2 password hash.
- Account passwords and 2FA secrets are **never** written to disk; they are forwarded to the activation service and discarded.
- Delete `data/` to reset all data (also resets the seeded admin).

---

## 🔐 Security Measures

Full detail lives in [SECURITY.md](SECURITY.md). In short:

- **Admin auth** — PBKDF2-SHA512 (100k iterations), signed httpOnly `sameSite=strict` session cookie, CSRF token on every write, identical responses for every failed login, per-IP and per-account throttling.
- **Key integrity** — atomic single-use claim (see above); used keys can never be re-enabled.
- **Public endpoints** — strict input validation, body size caps, per-IP/per-code/per-email rate limits, masked emails, and no CDK code in any public response.
- **Headers** — CSP, HSTS, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, no `X-Powered-By`.
- **Recon** — scanner user-agents and sensitive-path probes get an empty `404`; unknown paths render a generic page with no framework internals.

> ⚠️ **Production checklist**
> - [ ] Set a random `ADMIN_SECRET` (32+ chars): `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
> - [ ] Rotate the admin password with `npm run admin:password` — never leave `admin123` reachable.
> - [ ] Set `TRUSTED_PROXY_HOPS` to match your proxy setup.
> - [ ] Serve behind HTTPS (required for the secure cookie + HSTS).
> - [ ] Deploy with a persistent filesystem (the SQLite file must survive restarts).
> - [ ] Run `npm run audit:security` after every deploy.

---

## 📁 Project Structure

```
cdk-gateway/
├─ app/
│  ├─ page.tsx              # User site — Activate
│  ├─ guide/page.tsx        # User site — Guide
│  ├─ admin/page.tsx        # Admin panel page
│  ├─ api/
│  │  ├─ admin/login/…      # Admin auth
│  │  ├─ admin/keys/…       # Key CRUD (admin only)
│  │  └─ v1/
│  │     ├─ cdk/check/…     # Validate a key
│  │     ├─ cdk/activate/…  # Consume a key + start task
│  │     └─ task/status/…   # Task progress
│  ├─ layout.tsx            # Root layout + fonts + toasts
│  └─ globals.css
├─ components/
│  ├─ SiteShell.tsx         # Shared layout + language state
│  ├─ Navbar.tsx            # Nav + language selector + admin link
│  ├─ ActivatePage.tsx      # Mode tabs (Single / Check)
│  ├─ SingleMode.tsx        # 3-step activation flow
│  ├─ CheckMode.tsx         # Status lookup
│  ├─ GuidePage.tsx         # Guide content + video
│  ├─ AdminPanel.tsx        # Login + dashboard + key manager
│  ├─ NoteBox.tsx           # Checklist box
│  └─ Toast.tsx             # Toast notifications
├─ lib/
│  ├─ db.ts                 # SQLite schema + queries
│  ├─ auth.ts               # Password hashing + sessions
│  ├─ adminGuard.ts         # Shared session + CSRF check for admin routes
│  ├─ csrf.ts               # CSRF token issue/verify
│  ├─ ratelimit.ts          # Memory-capped rate limiter
│  ├─ net.ts                # Client IP, body size caps, cross-site detection
│  ├─ pixel.ts              # Pixel Partner API v2 client
│  ├─ mask.ts               # Email masking for public responses
│  ├─ validation.ts         # Input validation + attack pattern detection
│  ├─ seed.ts               # First-admin seeding
│  ├─ api.ts                # Client API helpers + types
│  └─ i18n.ts               # en / km / zh translations
├─ scripts/
│  ├─ security-audit.mjs    # Attack-simulation suite (npm run audit:security)
│  └─ set-admin-password.mjs# Password rotation (npm run admin:password)
├─ middleware.ts            # Edge filtering + rate limiting
└─ data/cdk.db              # SQLite database (auto-created)
```

---

## 🧪 Testing

```bash
npm run build
npm run audit:security
```

`scripts/security-audit.mjs` starts its own server on a **throwaway database** with
the Pixel API replaced by a local mock, then runs 60 checks against it: forged
sessions, missing and cross-site CSRF, SQL/XSS/traversal payloads, oversized
bodies, brute force, `X-Forwarded-For` spoofing, path probes, task-id guessing,
two simultaneous redemptions of one code, and the contents of the activity log.
Your real `data/cdk.db` is never opened, and the temporary one is deleted
afterwards.

---

## 📄 License

Private project. All rights reserved.
