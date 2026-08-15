# Security testing

## Automated suite

```bash
npm run build
npm run audit:security
```

This is the source of truth. `scripts/security-audit.mjs` starts its own
production server on a **temporary database**, with the Pixel Partner API
replaced by a local mock, so it never touches real keys and never submits a real
job. It prints one line per check and exits non-zero if anything fails.

What it covers:

| Group | Checks |
| --- | --- |
| Authentication | anonymous access, forged session cookie, login enumeration, brute-force throttling, cross-site login |
| CSRF | missing token, wrong token, valid token from a foreign origin |
| Injection | SQL, XSS and traversal payloads, oversized body, wrong content type, wrong method, non-Gmail address |
| Recon | `/.env`, `/.git/config`, `/wp-admin`, `*.php`, `*.sql`, `config.json`, scanner user-agent, generic 404, security headers, `robots.txt` |
| Keys | creation, duplicate handling, oversized batch, malformed id |
| Single use | two simultaneous redemptions of one code, reuse, re-enable, disabled key, release after a rejected submission |
| Exposure | code and password never echoed, masked email, guessed task id |
| Limits | forged `X-Forwarded-For`, code brute force |
| Activity log | contents, clamped page size, search, wildcard handling, filter injection |
| Upstream | a retryable error keeps the task running |

## Manual probing with Burp Suite (or any proxy)

The automated suite covers the same ground, but if you want to drive it by hand:

1. Point your browser at the proxy and browse the site normally. Use a **normal
   user-agent** — the middleware answers known scanner agents with an empty 404,
   which is a speed bump, not the actual defence.
2. **Replay an activation.** Capture a successful `POST /api/v1/cdk/activate`
   and send it again. Expect `409` — the code is consumed atomically before the
   upstream call.
3. **Race an activation.** Send the same request twice in parallel (Burp
   Intruder, or `curl` twice with `&`). Exactly one should get `200`, the other
   `409`, and only one upstream job should exist.
4. **Strip the CSRF header** from any admin write. Expect `403`.
5. **Change the `Origin`** on an admin write while keeping a valid token and
   cookie. Expect `403`.
6. **Tamper with the session cookie** — flip any character of the signature.
   Expect `401`.
7. **Enumerate task ids.** `GET /api/v1/task/status?task_id=…` with a guessed
   id returns `404`; the ids carry 60 bits of entropy.
8. **Rotate `X-Forwarded-For`** on repeated activations. With
   `TRUSTED_PROXY_HOPS` set correctly, injected left-hand entries do not create a
   fresh quota.
9. **Fuzz the inputs.** SQL, XSS, traversal, null bytes, 50 KB bodies, and
   non-JSON content types should all return `400`, `413` or `415` — never `500`,
   and never a stack trace.

## Reading the results

A `500` or a response containing a stack trace, file path, framework version or
SQL fragment is a finding worth fixing. `400`/`401`/`403`/`404`/`409`/`413`/`415`/`429`
with a short generic message is the expected behaviour.

See [SECURITY.md](SECURITY.md) for what each control does and for the list of
things that are deliberately not covered.
