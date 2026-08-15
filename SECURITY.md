# Security

This describes what the application actually enforces, where it is enforced, and
what is deliberately *not* covered. Every claim below is exercised by
`npm run audit:security` (60 checks, see the end of this file).

## Threat model

The application holds two things worth attacking:

1. **CDK keys** — each one is worth money, so the interesting attacks are
   redeeming one code twice, guessing codes, and creating codes without being an
   admin.
2. **Customer Google credentials** — they pass through the activation endpoint on
   their way to the Pixel Partner API. They are never stored, so the exposure
   window is a single request.

The admin panel is the highest-value target: it can mint keys.

## Admin authentication

| Control | Where |
| --- | --- |
| PBKDF2-SHA512, 100 000 iterations, 16-byte random salt per password | `lib/auth.ts` |
| Session = `username:expiry` signed with HMAC-SHA256, in an httpOnly `sameSite=strict` cookie, `secure` in production | `lib/auth.ts` |
| Constant-time hash comparison, with a length check first so a truncated hash cannot throw | `lib/auth.ts` |
| An unknown username still runs one PBKDF2 pass, so it cannot be told apart from a wrong password by timing | `lib/auth.ts` |
| Every failed login returns the same body and status (`401 Invalid credentials`) | `app/api/admin/login/route.ts` |
| 5 attempts/minute per IP, 10/minute per username, 60/minute globally | `app/api/admin/login/route.ts` |
| `ADMIN_SECRET` must be set, 32+ characters, and not the published example value — otherwise production refuses to sign sessions | `lib/auth.ts` |
| No default password in production: if `ADMIN_PASSWORD` is unset a random one is generated and printed once | `lib/seed.ts` |

Every admin route goes through one guard (`lib/adminGuard.ts`) that checks the
session, and for writes also the CSRF token and the request origin. There is no
admin endpoint that does its own ad-hoc check.

## CSRF

- A token is generated on login and returned in the JSON body; the panel echoes
  it back in an `x-csrf-token` header on every POST/PATCH/DELETE.
- The token is compared in constant time against the value in a paired cookie
  (`lib/csrf.ts`), and a length mismatch fails closed instead of throwing.
- The session cookie is `sameSite=strict`, so it is not sent on cross-site
  navigations at all.
- As defence in depth, writes with a foreign `Origin`/`Referer` are rejected
  before the token is even considered (`isCrossSite` in `lib/net.ts`). A stolen
  token is therefore not enough.

## Single-use keys

The guarantee is that a code can never enqueue two paid jobs:

1. `claimKey()` performs `UPDATE keys SET status='used' … WHERE id=? AND status='available'`.
   SQLite applies this atomically, so exactly one concurrent caller can match a row.
2. The claim happens **before** the upstream submission. The loser is rejected
   with `409` before any external work happens.
3. If the submission then fails (wrong password, no credit, upstream down),
   `releaseKey()` returns the code to `available`. On a *timeout* the code is
   released too, but a warning is logged because the job may exist upstream.
4. Codes are unique in the table and inserted with `ON CONFLICT DO NOTHING`.
5. A `used` key can never be re-enabled, not even by an admin.

## Public endpoints

`/api/v1/cdk/check`, `/api/v1/cdk/activate` and `/api/v1/task/status` are
unauthenticated by design — customers have no accounts.

- **Validation** — codes must match `MD-CDK-[A-Z0-9]{7,20}`; emails must be
  Gmail and RFC-length-valid; 2FA input is normalised and must yield a 32-char
  Base32 secret, optionally with 8-digit backup codes (`lib/validation.ts`, `lib/pixel.ts`).
- **Attack patterns** — SQL, XSS and traversal payloads are rejected with `400`
  before any query runs. All queries are prepared statements regardless.
- **Body size** — bodies are read through `readJsonBody` with a byte cap (4 KB
  for activation, 1 KB for a check), so a large payload gets `413` instead of
  being buffered.
- **No code echo** — `/task/status` returns neither the CDK code nor the full
  email; the address is masked to `jo•••••@gmail.com` (`lib/mask.ts`).
- **Task ids** — 60 bits of randomness from `crypto.randomBytes`, so the status
  endpoint cannot be enumerated. The previous format left only ~16 M candidates
  per minute.
- **Error messages** — upstream error codes are mapped through a fixed table;
  anything unrecognised becomes a generic message rather than being reflected
  (`mapError` in `lib/pixel.ts`).

## Rate limiting

In-memory, per key, fixed window (`lib/ratelimit.ts`). The map is swept
periodically and capped at 20 000 keys with oldest-first eviction, so it cannot
be grown into a memory-exhaustion vector.

| Scope | Limit |
| --- | --- |
| `/api/admin/*` per IP | 60 / min |
| `/api/v1/*` per IP | 30 / min |
| `/api/v1/cdk/activate` per IP | 5 / min |
| `/api/v1/cdk/check` per IP | 20 / min |
| activation, per email | 5 / 10 min |
| activation, per code | 10 / 10 min |
| activation and check, global | 120 and 600 / min |

The per-email and per-code buckets matter because they still apply when an
attacker rotates addresses, and the global caps still apply when the client IP
cannot be attributed at all.

**Client IP resolution** (`getClientIp` in `lib/net.ts`) reads
`X-Forwarded-For` `TRUSTED_PROXY_HOPS` entries from the right. With the default
of `1`, entries a client injects on the left are ignored because the real proxy
appends the true address last. Set it to `0` when the app is exposed directly, in
which case the header is not trusted at all. `CF-Connecting-IP` is only honoured
when `TRUST_CF_CONNECTING_IP=1`.

> If this value does not match your deployment, rate limiting is either
> bypassable (too high) or shared across all users (too low). It is the one
> setting worth double-checking.

## Edge filtering (`middleware.ts`)

- Sensitive-path probes (`/.env`, `/.git/*`, `/wp-admin`, `*.php`, `*.sql`,
  `config.json`, traversal sequences) get an **empty** `404` — no body, nothing
  to fingerprint. The patterns match path shapes, not keywords, so ordinary URLs
  are unaffected.
- Known scanner user-agents (sqlmap, nikto, nmap, nessus, metasploit, acunetix,
  burp's own agent, zgrab, …) get the same empty `404`.
- `POST`/`PATCH` to `/api/*` must be `application/json`, else `415`.
- Requests with no user-agent on write methods are rejected.

Scanner and path filtering is a speed bump, not a boundary: a proxy tool with a
normal user-agent gets through, which is why every route validates its own input.

## Response headers

Declared once in `next.config.mjs` so they also cover static assets:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';
  style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:;
  font-src 'self' data: https://fonts.gstatic.com; connect-src 'self'; object-src 'none';
  frame-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';
  upgrade-insecure-requests
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Cross-Origin-Opener-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload   (production)
```

`unsafe-eval` is present in development only (the React refresh runtime needs
it). `unsafe-inline` for scripts is still required by Next's inline bootstrap.
The Google Fonts origins must stay listed: without them the stylesheet is
blocked and the site silently falls back to a system font. `X-Powered-By` is
disabled, and `/api/*` and `/admin/*` are `noindex` (also via `robots.txt`).

## Error and 404 pages

`app/not-found.tsx` and `app/error.tsx` render a fixed message. No stack trace,
error digest, server path, framework version or route list reaches the client;
an unknown URL and a URL you are not allowed to see are indistinguishable.

## Activation log

Every activation writes a `tasks` row with the code, account email, outcome,
progress, failure reason, client IP, user agent (capped at 400 chars) and
timestamps. The admin panel shows this under **Activity Log** with status
filters, search across email/code/task id/IP, paging and CSV export. Search
terms are parameterised and `%`/`_` are escaped, so a wildcard is matched
literally. The CSV escapes leading `=+-@` so a cell cannot become a spreadsheet
formula.

Account passwords and 2FA secrets are never written to the database, the log, or
any response.

## What is not covered

Being explicit about the gaps is more useful than a checklist of ticks:

- **Rate limiting is per-process and in memory.** Restarting clears it, and
  running multiple instances multiplies every limit. A shared store (Redis) is
  needed for a real cluster.
- **No 2FA on the admin login.** Password plus throttling is the only barrier.
- **No audit trail for admin actions.** Key creation and deletion are not logged.
- **A determined proxy user is not blocked.** Scanner detection is user-agent
  based and trivially spoofed; the real defences are the validation, CSRF, and
  single-use logic behind it.
- **SQLite is a single file.** Back up `data/cdk.db` (and its `-wal`); there is
  no replication.
- **The upstream API is trusted** to not return malicious content.

## Verifying

```bash
npm run build
npm run audit:security
```

The script starts its own production server on a temporary database with a mocked
Pixel API, runs 60 attack scenarios, prints a pass/fail line for each, and exits
non-zero on any failure. Your real database is never opened.

Rotate the admin password any time with `npm run admin:password`.
