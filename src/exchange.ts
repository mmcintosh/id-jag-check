// Minting the ID-JAG to check: the token exchange of draft -06 section 4.3, sent to your IdP's token endpoint. Its
// answer is checked with better-auth-id-jag's checkExchange (section 4.3.4), the rules the public tester uses for it.
// Only used when the workflow doesn't pass an ID-JAG in.
import { checkExchange, type ExchangeReport, ID_JAG_TOKEN_TYPE, ID_TOKEN_TOKEN_TYPE, REFRESH_TOKEN_TOKEN_TYPE, type RuleResult, SAML2_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT } from "better-auth-id-jag";
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
  if (!answer.ok) {
    add("exchange.status", "MUST", `${D("4.3.4")}; RFC 8693 section 2.2.1`, "fail", `Your token endpoint ${answer.why}.`);
    return { token: null, results };
  }
  // A body that isn't JSON, or is nested too deeply to check, is given to the checker as not JSON.
  const parsed = parseJson(answer.body);
  let report: ExchangeReport;
  try {
    report = checkExchange({
      status: answer.status,
      contentType: answer.headers.get("content-type"),
      cacheControl: answer.headers.get("cache-control"),
      body: parsed.ok ? parsed.json : undefined,
      requestedScope: input.scopes.join(" "),
      requestedResources: [input.resource],
    });
  } catch {
    // The checker isn't known to throw on any input; if it ever does, that is a failed rule, and the rest of the
    // report is kept.
    add("exchange.check", "MUST", D("4.3.4"), "fail", "Your token endpoint's answer has a value the checks couldn't read, so they stopped.");
    return { token: null, results };
  }
  // A refusal shows the error code only: an error_description can name the user, and this report goes into the job's
  // log. checkExchange's message for it quotes the description, so it is replaced.
  const error = report.error;
  results.push(...report.results.map((r) => (r.id === "exchange.status" && error ? { ...r, message: refused(answer.status, error.code) } : r)));
  return { token: report.idJag, results };
}

function refused(status: number, code: string): string {
  return status === 200
    ? `Your token endpoint refused the exchange with error ${show(code)}, but with HTTP 200: an error response is HTTP 400, or 401 for failed client authentication (RFC 6749 section 5.2).`
    : `Your token endpoint refused the exchange: HTTP ${status} with error ${show(code)}.`;
}
