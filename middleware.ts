import { NextRequest, NextResponse } from "next/server";

import { getClientIp } from "@/lib/net";
import { hit } from "@/lib/ratelimit";

/**
 * Edge-level request filtering: cheap, generic protections applied before any
 * route handler runs. Anything needing the database (auth, CSRF, single-use
 * claims) is enforced in the route handlers, and response security headers are
 * declared in next.config.mjs.
 */

/**
 * Probes for files that only exist on misconfigured deployments. Matched
 * against the decoded pathname only — never the host or the whole URL, because
 * a substring blocklist over the full URL breaks every request as soon as the
 * site is hosted on a domain that happens to contain one of the words.
 */
const PATH_PROBES = [
  /\.\./,
  /\/\.(env|git|ssh|aws|npmrc|htpasswd)/i,
  /\/(wp-admin|wp-login|phpmyadmin|adminer|\.well-known\/security\.txt$)/i,
  /\.(php|asp|aspx|jsp|cgi|bak|sql|sqlite|db|log|ini|conf|pem|key)$/i,
  /\/(config|backup|dump|credentials)\.(json|ya?ml|xml|txt)$/i,
];

/**
 * Default user-agents of common scanners. This only stops unconfigured tools —
 * any real attacker changes the header in one click — so it must never be
 * treated as a security control on its own.
 */
const SCANNER_AGENTS = [
  /sqlmap/i,
  /nikto/i,
  /nmap|zgrab|masscan/i,
  /nessus|acunetix|qualys|openvas/i,
  /metasploit|havij|dirbuster|gobuster|feroxbuster|wpscan/i,
];

/** Absolute ceilings that hold even if per-client identification is defeated. */
const GLOBAL_LIMITS: Record<string, { limit: number; windowMs: number }> = {
  activate: { limit: 120, windowMs: 60_000 },
  check: { limit: 600, windowMs: 60_000 },
};

function isProbe(pathname: string): boolean {
  let decoded = pathname;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    // Undecodable percent-escapes are themselves a bad sign.
    return true;
  }
  return PATH_PROBES.some((re) => re.test(decoded));
}

function isScanner(userAgent: string): boolean {
  return SCANNER_AGENTS.some((re) => re.test(userAgent));
}

function jsonError(message: string, status: number, retryAfter?: number): NextResponse {
  const res = NextResponse.json({ success: false, error: message }, { status });
  if (retryAfter) res.headers.set("retry-after", String(retryAfter));
  return res;
}

function contentTypeOk(req: NextRequest): boolean {
  if (req.method !== "POST" && req.method !== "PATCH" && req.method !== "PUT") return true;
  if (!req.nextUrl.pathname.startsWith("/api/")) return true;
  return (req.headers.get("content-type") || "").includes("application/json");
}

export function middleware(req: NextRequest) {
  const pathname = req.nextUrl.pathname;
  const userAgent = req.headers.get("user-agent") || "";
  const isApi = pathname.startsWith("/api/");

  // 1. Obvious probes and default-configured scanners get nothing useful back.
  if (isProbe(pathname) || isScanner(userAgent)) {
    return new NextResponse(null, { status: 404 });
  }

  // 2. API writes must be JSON; anything else is a malformed or forged request.
  if (!contentTypeOk(req)) {
    return jsonError("Unsupported Media Type", 415);
  }

  if (isApi) {
    const ip = getClientIp(req);

    // 3. Per-client limits, in separate buckets so admin traffic and public
    //    traffic cannot consume each other's budget.
    if (pathname.startsWith("/api/admin/")) {
      const r = hit(`admin:${ip}`, 60, 60_000);
      if (r.limited) return jsonError("Too many requests. Please try again later.", 429, r.retryAfter);
    } else if (pathname.startsWith("/api/v1/")) {
      const r = hit(`v1:${ip}`, 30, 60_000);
      if (r.limited) return jsonError("Too many requests. Please try again later.", 429, r.retryAfter);
    }

    // 4. The activation endpoint is the one with real-world cost attached.
    if (pathname === "/api/v1/cdk/activate") {
      if (req.method !== "POST") return jsonError("Method Not Allowed", 405);
      if (!userAgent) return jsonError("Bad Request", 400);

      const perIp = hit(`activate:${ip}`, 5, 60_000);
      if (perIp.limited) {
        return jsonError(
          "Too many activation attempts. Please wait before trying again.",
          429,
          perIp.retryAfter
        );
      }

      // Holds even when a client forges its way into fresh per-IP buckets.
      const global = hit("global:activate", GLOBAL_LIMITS.activate.limit, GLOBAL_LIMITS.activate.windowMs);
      if (global.limited) {
        return jsonError("The service is busy. Please try again shortly.", 429, global.retryAfter);
      }
    }

    // 5. The check endpoint is a validity oracle, so cap guessing globally too.
    if (pathname === "/api/v1/cdk/check") {
      if (req.method !== "POST") return jsonError("Method Not Allowed", 405);

      const perIp = hit(`check:${ip}`, 20, 60_000);
      if (perIp.limited) {
        return jsonError("Too many code checks. Please wait a moment.", 429, perIp.retryAfter);
      }
      const global = hit("global:check", GLOBAL_LIMITS.check.limit, GLOBAL_LIMITS.check.windowMs);
      if (global.limited) {
        return jsonError("The service is busy. Please try again shortly.", 429, global.retryAfter);
      }
    }
  }

  // Security headers are declared in next.config.mjs so they also cover the
  // static assets this matcher skips.
  return NextResponse.next();
}

export const config = {
  matcher: [
    // Everything except Next's own static output and image files, which need no
    // filtering and would only add latency.
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)",
  ],
};
