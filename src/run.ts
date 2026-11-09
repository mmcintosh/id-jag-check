// One run: find your issuer's metadata and keys, check them, get the ID-JAG (passed in, or minted), and check it.
// Every rule comes from better-auth-id-jag's checkIssuerMetadata and checkIdJag, so this Action and the public
// tester hold an IdP to the same rules; the few rules here are about fetching and minting, which only the Action does.
import { checkIdJag, checkIssuerMetadata, type IdJagReport, type RuleResult } from "better-auth-id-jag";
import { type MintInput, mint } from "./exchange.js";
import { checkHttpsUrl, type FetchLike, getJson, oauthMetadataUrl, openIdConfigurationUrl } from "./http.js";

export type FailOn = "fail" | "warn";

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
  /** The ids of the rules that stop the step (fail, and warn when failOn is "warn"). */
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
  let metadata: Record<string, unknown> | null = null;
  let jwks: unknown = null;
  if (meta.ok && isObject(meta.json)) {
    metadata = meta.json;
    const jwksUri = typeof metadata.jwks_uri === "string" ? metadata.jwks_uri : null;
    const keys = jwksUri ? await getJson(fetchImpl, jwksUri) : ({ ok: false, why: "has no jwks_uri to fetch" } as const);
    if (keys.ok) jwks = keys.json;
    results.push(...checkIssuerMetadata({ issuer: input.issuer, source, metadata, jwks }).results);
    if (!keys.ok) results.push({ id: "jwks.fetch", level: "MUST", cite: "draft -06 section 7.1", outcome: "fail", message: `Your JWKS ${keys.why}.` });
  } else {
    const why = meta.ok ? "isn't a JSON object" : meta.why;
    results.push({ id: "metadata.fetch", level: "SHOULD", cite: "draft -06 section 7.1; RFC 8414 section 3", outcome: "fail", message: `No metadata at ${oauthMetadataUrl(issuerUrl.url)} (${why}) or at ${openIdConfigurationUrl(issuerUrl.url)}: a receiver finds your keys there.` });
  }

  // The ID-JAG.
  let token: string | null;
  let minted: string | null = null;
  if ("token" in input.idJag) token = input.idJag.token;
  else {
    const endpoint = input.idJag.mint.tokenEndpoint ?? (typeof metadata?.token_endpoint === "string" ? metadata.token_endpoint : undefined);
    if (!endpoint) throw new InputError("token-endpoint is needed to mint an ID-JAG: your metadata has no token_endpoint.");
    const exchange = await mint(fetchImpl, { ...input.idJag.mint, tokenEndpoint: endpoint });
    results.push(...exchange.results);
    token = exchange.token;
    minted = exchange.token;
  }

  let header: IdJagReport["header"] = null;
  let claims: IdJagReport["claims"] = null;
  if (token !== null) {
    const report = await checkIdJag(token, {
      issuer: input.issuer,
      audience: input.audience,
      resource: input.resource,
      grantableScopes: input.scopes,
      clientId: input.clientId,
      jwks: isObject(jwks) && Array.isArray(jwks.keys) ? (jwks as unknown as Parameters<typeof checkIdJag>[1]["jwks"]) : null,
      now: input.now,
    });
    results.push(...report.results);
    header = report.header;
    claims = report.claims;
  }

  const failed = results.filter((r) => r.outcome === "fail" || (input.failOn === "warn" && r.outcome === "warn")).map((r) => r.id);
  return { results, header, claims, failed, passed: failed.length === 0 && token !== null, minted };
}

/** A problem with the workflow's inputs, not with the IdP: the step fails with this message alone. */
export class InputError extends Error {}
