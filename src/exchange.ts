// Minting the ID-JAG to check: the token exchange of draft -06 section 4.3, sent to your IdP's token endpoint, and
// the rules for its answer (section 4.3.4). Only used when the workflow doesn't pass an ID-JAG in.
import { ID_JAG_TOKEN_TYPE, ID_TOKEN_TOKEN_TYPE, REFRESH_TOKEN_TOKEN_TYPE, type RuleResult, SAML2_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT } from "better-auth-id-jag";
import { type FetchLike, parseJson, request } from "./http.js";
import { show } from "./show.js";

export const SUBJECT_TOKEN_TYPES = { id_token: ID_TOKEN_TOKEN_TYPE, refresh_token: REFRESH_TOKEN_TOKEN_TYPE, saml2: SAML2_TOKEN_TYPE } as const;
export type SubjectTokenType = keyof typeof SUBJECT_TOKEN_TYPES;
export const CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post"] as const;
export type ClientAuthMethod = (typeof CLIENT_AUTH_METHODS)[number];

export interface MintInput {
  tokenEndpoint: string;
  /** The client's id and secret at your IdP (not at the receiver). */
  clientId: string;
  clientSecret: string;
  clientAuth: ClientAuthMethod;
  subjectToken: string;
  subjectTokenType: SubjectTokenType;
  /** The receiver's issuer identifier. */
  audience: string;
  resource: string;
  scopes: readonly string[];
}

const D = (section: string) => `draft -06 section ${section}`;

/** application/x-www-form-urlencoded, as RFC 6749 section 2.3.1 asks for both halves of HTTP Basic credentials. */
const formEncode = (s: string) => new URLSearchParams([["", s]]).toString().slice(1);

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** Asks your IdP for an ID-JAG. `token` is null when there's none to check; `results` says why. Never throws. */
export async function mint(fetchImpl: FetchLike, input: MintInput): Promise<{ token: string | null; results: RuleResult[] }> {
  const results: RuleResult[] = [];
  const add = (id: string, level: RuleResult["level"], cite: string, outcome: RuleResult["outcome"], message: string) => results.push({ id, level, cite, outcome, message });

  const form = new URLSearchParams({
    grant_type: TOKEN_EXCHANGE_GRANT,
    requested_token_type: ID_JAG_TOKEN_TYPE,
    audience: input.audience,
    resource: input.resource,
    scope: input.scopes.join(" "),
    subject_token: input.subjectToken,
    subject_token_type: SUBJECT_TOKEN_TYPES[input.subjectTokenType],
  });
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded", accept: "application/json" };
  if (input.clientAuth === "client_secret_basic") headers.authorization = `Basic ${btoa(`${formEncode(input.clientId)}:${formEncode(input.clientSecret)}`)}`;
  else {
    form.set("client_id", input.clientId);
    form.set("client_secret", input.clientSecret);
  }

  const answer = await request(fetchImpl, input.tokenEndpoint, { method: "POST", headers, body: form.toString() });
  const cite = `${D("4.3.4")}; RFC 8693 section 2.2`;
  if (!answer.ok) {
    add("exchange.response", "MUST", cite, "fail", `Your token endpoint ${answer.why}.`);
    return { token: null, results };
  }
  const parsed = parseJson(answer.body);
  const json = parsed.ok ? parsed.json : undefined;
  if (answer.status !== 200 || !isObject(json)) {
    // The error code only: an error_description can name the user, and this report goes into the job's log.
    const error = isObject(json) && typeof json.error === "string" ? ` with error ${show(json.error)}` : "";
    add("exchange.response", "MUST", cite, "fail", answer.status === 200 ? `Your token endpoint answered 200, but not with a JSON object${parsed.ok ? "" : ` (it ${parsed.why})`}.` : `Your token endpoint refused the exchange: HTTP ${answer.status}${error}.`);
    return { token: null, results };
  }
  add("exchange.response", "MUST", cite, "pass", "Your token endpoint answered the exchange with HTTP 200 and a JSON object.");

  const issued = json.issued_token_type;
  add("exchange.issued_token_type", "MUST", D("4.3.4"), issued === ID_JAG_TOKEN_TYPE ? "pass" : "fail", issued === ID_JAG_TOKEN_TYPE ? `issued_token_type is ${ID_JAG_TOKEN_TYPE}.` : `issued_token_type is REQUIRED: ${ID_JAG_TOKEN_TYPE}; it is ${show(issued)}.`);
  const tokenType = json.token_type;
  const naOk = typeof tokenType === "string" && tokenType.toLowerCase() === "n_a";
  add("exchange.token_type", "MUST", `${D("4.3.4")}; RFC 6749 section 5.1`, naOk ? "pass" : "fail", naOk ? "token_type is N_A (this is not an access token)." : `token_type is REQUIRED: N_A, because an ID-JAG is not an access token; it is ${show(tokenType)}.`);
  const cacheControl = answer.headers.get("cache-control") ?? "";
  const noStore = cacheControl.split(",").some((d) => d.trim().toLowerCase() === "no-store");
  const contentType = (answer.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase() ?? "";
  add("exchange.content_type", "MUST", "RFC 6749 section 5.1; RFC 8693 section 2.2.1", contentType === "application/json" ? "pass" : "fail", contentType === "application/json" ? "Content-Type: application/json." : `A token response is application/json; its Content-Type is ${contentType ? show(contentType) : "absent"}.`);
  add("exchange.cache_control", "MUST", "RFC 6749 section 5.1; RFC 8693 section 2.2", noStore ? "pass" : "fail", noStore ? "Cache-Control: no-store." : `A token response MUST carry Cache-Control: no-store; it has ${cacheControl ? show(cacheControl) : "none"}.`);
  const expiresIn = json.expires_in;
  const expiresOk = typeof expiresIn === "number" && Number.isInteger(expiresIn) && expiresIn > 0;
  add("exchange.expires_in", "RECOMMENDED", D("4.3.4"), expiresOk ? "pass" : "warn", expiresOk ? `expires_in is ${expiresIn} s.` : `expires_in (the ID-JAG's lifetime in seconds) is RECOMMENDED; it is ${expiresIn === undefined ? "absent" : show(expiresIn)}.`);
  add("exchange.refresh_token", "SHOULD", D("4.3.4"), json.refresh_token === undefined ? "pass" : "warn", json.refresh_token === undefined ? "No refresh_token." : "A refresh_token SHOULD NOT be returned with an ID-JAG.");

  const token = json.access_token;
  if (typeof token !== "string" || token.length === 0) {
    add("exchange.access_token", "MUST", D("4.3.4"), "fail", "access_token is REQUIRED: it carries the ID-JAG.");
    return { token: null, results };
  }
  add("exchange.access_token", "MUST", D("4.3.4"), "pass", "access_token carries the ID-JAG.");

  // scope: "OPTIONAL if the scope of the issued token is identical to the scope requested by the client; otherwise,
  // it is REQUIRED" (section 4.3.4). The issued scope is the ID-JAG's scope claim.
  // Compared as sets, so a repeated scope ("read read") can't stand in for a missing one.
  const issuedScope = scopeClaim(token);
  const same = issuedScope !== null && sameSet(issuedScope, input.scopes);
  if (json.scope !== undefined) {
    const returned = typeof json.scope === "string" ? json.scope.split(" ").filter(Boolean) : null;
    const matches = returned !== null && (issuedScope === null || sameSet(returned, issuedScope));
    add("exchange.scope", "OPTIONAL", D("4.3.4"), matches ? "pass" : "fail", returned === null ? "scope must be a space-separated string." : matches ? `scope ${show(json.scope)} is returned.` : `scope ${show(json.scope)} is returned, but the ID-JAG's scope claim is ${show(issuedScope?.join(" "))}: the response's scope is the issued token's scope.`);
  }
  else add("exchange.scope", "MUST", D("4.3.4"), same ? "pass" : "fail", same ? "No scope returned, and the ID-JAG grants exactly the scopes requested (allowed: OPTIONAL when identical)." : "No scope returned, but the ID-JAG's scope differs from the scopes requested: the response then MUST include scope.");

  return { token, results };
}

const sameSet = (a: readonly string[], b: readonly string[]) => {
  const x = new Set(a);
  const y = new Set(b);
  return x.size === y.size && [...x].every((s) => y.has(s));
};

/** The ID-JAG's scope claim as a list, without verifying it (the checker does that), or null if it has none. */
function scopeClaim(token: string): string[] | null {
  const part = token.split(".")[1];
  if (!part) return null;
  try {
    const claims: unknown = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    return isObject(claims) && typeof claims.scope === "string" ? claims.scope.split(" ").filter(Boolean) : null;
  } catch {
    return null;
  }
}
