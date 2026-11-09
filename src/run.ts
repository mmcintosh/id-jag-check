// One run: find your issuer's metadata and keys, check them, get the ID-JAG (passed in, or minted), and check it.
// Every rule comes from better-auth-id-jag's checkIssuerMetadata and checkIdJag, so this Action and the public
// tester hold an IdP to the same rules; the few rules here are about fetching and minting, which only the Action does.
import { checkIdJag, checkIssuerMetadata, type IdJagReport, type RuleResult } from "better-auth-id-jag";
import { type MintInput, mint } from "./exchange.js";
import { checkHttpsUrl, type FetchLike, getJson, oauthMetadataUrl, openIdConfigurationUrl } from "./http.js";
import { show, tooDeep } from "./show.js";

/**
 * What stops the step. must: a failed MUST of the draft or an RFC, or a rule that stops a receiver's registration
 * (checkIssuerMetadata's `blocking`). policy: also a failed POLICY rule, what better-auth-id-jag's receiver refuses
 * though the draft allows it. warn: any failed rule, and any warning.
 */
export const FAIL_ON = ["must", "policy", "warn"] as const;
export type FailOn = (typeof FAIL_ON)[number];

export interface RunInput {
  issuer: string;
  /** The receiver's issuer identifier: the ID-JAG's aud. */
  audience: string;
  /** The protected resource the receiver governs. */
  resource: string;
  /** The scopes the receiver grants. */
  scopes: readonly string[];
  /** The client's id at the receiver: the ID-JAG's client_id. */
  clientId: string | undefined;
  /** The ID-JAG to check, or how to mint one. */
  idJag: { token: string } | { mint: Omit<MintInput, "tokenEndpoint"> & { tokenEndpoint: string | undefined } };
  failOn: FailOn;
  /** Unix seconds. */
  now: number;
}

export interface RunResult {
  results: RuleResult[];
  /** The ID-JAG's header and claims, when there was one to decode. */
  header: IdJagReport["header"];
  claims: IdJagReport["claims"];
  /** The ids of the rules that stop the step, as failOn says. */
  failed: string[];
  passed: boolean;
  /** A minted ID-JAG, so the caller can mask it before anything is printed. */
  minted: string | null;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

export async function run(input: RunInput, fetchImpl: FetchLike): Promise<RunResult> {
  const results: RuleResult[] = [];
  const issuerUrl = checkHttpsUrl(input.issuer);
  if (!issuerUrl.ok) throw new InputError(`issuer ${issuerUrl.why}.`);
  // RFC 8414 section 2: an issuer identifier has no query or fragment.
  if (issuerUrl.url.search) throw new InputError("issuer must not contain a query (?): RFC 8414 section 2.");

  // Metadata: RFC 8414's location first, then OpenID Connect Discovery's (the fallback draft -06 section 7.1 allows).
  let source: "oauth-authorization-server" | "openid-configuration" = "oauth-authorization-server";
  let meta = await getJson(fetchImpl, oauthMetadataUrl(issuerUrl.url));
  if (!meta.ok || !isObject(meta.json)) {
    const fallback = await getJson(fetchImpl, openIdConfigurationUrl(issuerUrl.url));
    if (fallback.ok && isObject(fallback.json)) {
      meta = fallback;
      source = "openid-configuration";
    }
  }
  // Metadata whose issuer isn't exactly the one asked for MUST NOT be used (RFC 8414 section 3.3, draft -06 section
  // 9.5): then neither its jwks_uri nor its token_endpoint is used, so no secret goes to an endpoint it names.
  let metadata: Record<string, unknown> | null = null;
  let jwks: unknown = null;
  let blocking: string[] = [];
  const JWKS_FETCH = { id: "jwks.fetch", level: "MUST", cite: "draft -06 section 4.4.1; RFC 7521 section 5.2" } as const;
  if (meta.ok && isObject(meta.json)) {
    metadata = meta.json;
    const usable = metadata.issuer === input.issuer;
    const jwksUri = typeof metadata.jwks_uri === "string" ? metadata.jwks_uri : null;
    const keys = !usable ? null : jwksUri ? await getJson(fetchImpl, jwksUri) : ({ ok: false, why: "has no jwks_uri to fetch" } as const);
    if (keys?.ok) jwks = keys.json;
    const checked = guard(() => checkIssuerMetadata({ issuer: input.issuer, source, metadata: metadata as Record<string, unknown>, jwks }));
    if (checked.ok) {
      results.push(...checked.value.results);
      blocking = checked.value.blocking;
    } else results.push({ id: "metadata.check", level: "MUST", cite: "RFC 8414 section 3.2", outcome: "fail", message: "Your metadata or JWKS has a value the checks couldn't read, so they stopped." });
    if (keys === null) results.push({ ...JWKS_FETCH, outcome: "skip", message: "Not fetched: metadata whose issuer doesn't match MUST NOT be used (RFC 8414 section 3.3), so neither is its jwks_uri." });
    else if (!keys.ok) results.push({ ...JWKS_FETCH, outcome: "fail", message: `Your JWKS ${keys.why}: a receiver verifies the ID-JAG's signature with these keys.` });
  } else {
    const why = meta.ok ? "isn't a JSON object" : meta.why;
    results.push({ id: "metadata.fetch", level: "SHOULD", cite: "draft -06 section 7.1; RFC 8414 section 3", outcome: "fail", message: `No metadata at ${oauthMetadataUrl(issuerUrl.url)} (${why}) or at ${openIdConfigurationUrl(issuerUrl.url)}: a receiver finds your keys there.` });
    results.push({ ...JWKS_FETCH, outcome: "fail", message: "Without metadata there is no jwks_uri, so a receiver can't find the keys to verify the ID-JAG's signature." });
  }

  // The ID-JAG.
  let token: string | null;
  let minted: string | null = null;
  if ("token" in input.idJag) token = input.idJag.token;
  else {
    const fromMetadata = metadata?.issuer === input.issuer && typeof metadata.token_endpoint === "string" ? metadata.token_endpoint : undefined;
    const endpoint = input.idJag.mint.tokenEndpoint ?? fromMetadata;
    if (endpoint) {
      const exchange = await mint(fetchImpl, { ...input.idJag.mint, tokenEndpoint: endpoint });
      results.push(...exchange.results);
      token = exchange.token;
      minted = exchange.token;
    } else {
      const why = metadata === null ? "no metadata was found" : metadata.issuer !== input.issuer ? "your metadata's issuer doesn't match, so its token_endpoint MUST NOT be used (RFC 8414 section 3.3)" : "your metadata has no token_endpoint";
      results.push({ id: "exchange.token_endpoint", level: "MUST", cite: "RFC 8414 sections 2, 3.3", outcome: "fail", message: `Not minted: ${why}. Fix it, or give the token-endpoint input.` });
      token = null;
    }
  }

  let header: IdJagReport["header"] = null;
  let claims: IdJagReport["claims"] = null;
  if (token !== null && tooDeepToken(token)) {
    results.push({ id: "jwt.structure", level: "MUST", cite: "RFC 7519 section 7.2", outcome: "fail", message: "The header or the claims are nested too deeply to check." });
  } else if (token !== null) {
    const checked = await guardAsync(() => checkIdJag(token, {
      issuer: input.issuer,
      audience: input.audience,
      resource: input.resource,
      grantableScopes: input.scopes,
      clientId: input.clientId,
      jwks: isObject(jwks) && Array.isArray(jwks.keys) ? (jwks as unknown as Parameters<typeof checkIdJag>[1]["jwks"]) : null,
      now: input.now,
    }));
    // A value the checker couldn't read (such as a malformed certificate in your JWKS) is a failed rule, and the
    // rest of the report is kept.
    const report: IdJagReport = checked.ok ? checked.value : { header: null, claims: null, results: [{ id: "jwt.check", level: "MUST", cite: "draft -06 section 4.4.1", outcome: "fail", message: "The ID-JAG or your JWKS has a value the checks couldn't read (a malformed x5c certificate, for example), so they stopped." }] };
    // receiver.parse is whether better-auth-id-jag's own receiver accepts the ID-JAG: that receiver's policy. Every
    // MUST it enforces has its own rule above, so here it's POLICY, and fail-on: must doesn't stop on it alone.
    results.push(...report.results.map((r) => ({ ...r, level: r.id === "receiver.parse" ? ("POLICY" as const) : r.level, message: hideUserValues(r.message, report.claims) })));
    header = report.header;
    claims = report.claims;
  }

  const stops = (r: RuleResult) =>
    input.failOn === "warn" ? r.outcome === "fail" || r.outcome === "warn" : r.outcome === "fail" && (r.level === "MUST" || blocking.includes(r.id) || (input.failOn === "policy" && r.level === "POLICY"));
  const failed = results.filter(stops).map((r) => r.id);
  return { results, header, claims, failed, passed: failed.length === 0 && token !== null, minted };
}

/** The claims whose values the report may show: they say which IdP, receiver and client this is, not who the user is. */
export const SHOWN_CLAIMS = ["iss", "aud", "client_id", "resource", "scope", "jti", "iat", "exp", "nbf", "tenant"] as const;

/**
 * A checker message with every value about the user taken out: each string inside a claim not in SHOWN_CLAIMS (sub,
 * email, act.sub...), in the form the checker's messages quote it.
 */
function hideUserValues(message: string, claims: IdJagReport["claims"]): string {
  if (!claims) return message;
  const values: string[] = [];
  const collect = (v: unknown, depth: number) => {
    if (typeof v === "string") values.push(show(v));
    else if (depth < 8 && typeof v === "object" && v !== null) for (const x of Object.values(v)) collect(x, depth + 1);
  };
  for (const [name, value] of Object.entries(claims)) if (!(SHOWN_CLAIMS as readonly string[]).includes(name)) collect(value, 0);
  // Longest first, so a value that contains another is taken out whole.
  return values.sort((a, b) => b.length - a.length).reduce((m, v) => m.split(v).join("(not shown)"), message);
}

type Guarded<T> = { ok: true; value: T } | { ok: false };
function guard<T>(f: () => T): Guarded<T> {
  try {
    return { ok: true, value: f() };
  } catch {
    return { ok: false };
  }
}
async function guardAsync<T>(f: () => Promise<T>): Promise<Guarded<T>> {
  try {
    return { ok: true, value: await f() };
  } catch {
    return { ok: false };
  }
}

/** Whether the token's header or claims are nested deeper than anything the checks need (they'd overflow the stack). */
function tooDeepToken(token: string): boolean {
  return token.split(".").slice(0, 2).some((part) => {
    try {
      return tooDeep(JSON.parse(Buffer.from(part, "base64url").toString("utf8")));
    } catch {
      return false;
    }
  });
}

/** A problem with the workflow's inputs, not with the IdP: the step fails with this message alone. */
export class InputError extends Error {}
