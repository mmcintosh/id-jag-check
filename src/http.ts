// The only requests this Action makes: your issuer's metadata, its JWKS, and (when it mints the ID-JAG) its token
// endpoint. Each is https only, never follows a redirect, stops reading past a size cap and gives up after a timeout,
// so a misconfigured input can't send the Action anywhere unexpected or make it download much.

import { MAX_DEPTH, tooDeep } from "./show.js";

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export const MAX_URL_LENGTH = 2048;
export const MAX_BYTES = 262_144;
export const TIMEOUT_MS = 10_000;

export type UrlCheck = { ok: true; url: URL } | { ok: false; why: string };

/** An https URL with no user name, password or fragment. */
export function checkHttpsUrl(raw: string): UrlCheck {
  if (raw.length === 0 || raw.length > MAX_URL_LENGTH) return { ok: false, why: `must be a URL of at most ${MAX_URL_LENGTH} characters` };
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, why: "is not a URL" };
  }
  if (url.protocol !== "https:") return { ok: false, why: "must use https" };
  if (url.username || url.password) return { ok: false, why: "must not contain a user name or password" };
  if (url.hash) return { ok: false, why: "must not contain a fragment (#)" };
  return { ok: true, url };
}

export type Answer = { ok: true; status: number; headers: Headers; body: string } | { ok: false; why: string };

/** One request: https only, no redirects, at most MAX_BYTES read, within TIMEOUT_MS. Never throws. */
export async function request(fetchImpl: FetchLike, raw: string, init: RequestInit = {}, timeoutMs = TIMEOUT_MS): Promise<Answer> {
  const check = checkHttpsUrl(raw);
  if (!check.ok) return { ok: false, why: `the URL ${check.why}` };
  const signal = AbortSignal.timeout(timeoutMs);
  try {
    const response = await fetchImpl(check.url.href, { ...init, redirect: "manual", signal });
    // A refused answer's body is cancelled, so its connection doesn't stay open until the timeout.
    const refuse = async (why: string): Promise<Answer> => {
      await response.body?.cancel().catch(() => {});
      return { ok: false, why };
    };
    if (response.status >= 300 && response.status < 400) return refuse(`answered ${response.status} (a redirect, which this Action doesn't follow)`);
    const declared = Number(response.headers.get("content-length") ?? "0");
    if (declared > MAX_BYTES) return refuse(`answered with more than ${MAX_BYTES} bytes`);
    const reader = response.body?.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (reader) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BYTES) {
        await reader.cancel();
        return { ok: false, why: `answered with more than ${MAX_BYTES} bytes` };
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const c of chunks) {
      bytes.set(c, offset);
      offset += c.byteLength;
    }
    return { ok: true, status: response.status, headers: response.headers, body: new TextDecoder().decode(bytes) };
  } catch {
    return { ok: false, why: signal.aborted ? `didn't answer within ${timeoutMs / 1000} s` : "couldn't be reached" };
  }
}

export type JsonAnswer = { ok: true; json: unknown } | { ok: false; why: string };

/** JSON from a response body, or why not: not JSON, or nested deeper than MAX_DEPTH. Never throws. */
export function parseJson(body: string): JsonAnswer {
  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch {
    return { ok: false, why: "is not JSON" };
  }
  return tooDeep(json) ? { ok: false, why: `is JSON nested more than ${MAX_DEPTH} levels deep` } : { ok: true, json };
}

/** GETs a JSON document through `request`. Never throws. */
export async function getJson(fetchImpl: FetchLike, raw: string): Promise<JsonAnswer> {
  const answer = await request(fetchImpl, raw, { method: "GET", headers: { accept: "application/json" } });
  if (!answer.ok) return answer;
  if (answer.status !== 200) return { ok: false, why: `answered HTTP ${answer.status}` };
  return parseJson(answer.body);
}

/** RFC 8414 section 3.1: the well-known segment goes between the host and the issuer's path. */
export function oauthMetadataUrl(issuer: URL): string {
  const path = issuer.pathname === "/" ? "" : issuer.pathname.replace(/\/$/, "");
  return `${issuer.origin}/.well-known/oauth-authorization-server${path}`;
}

/** OpenID Connect Discovery 1.0 section 4: appended to the issuer. */
export function openIdConfigurationUrl(issuer: URL): string {
  return `${issuer.href.replace(/\/$/, "")}/.well-known/openid-configuration`;
}
