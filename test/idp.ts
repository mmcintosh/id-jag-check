// A fake IdP for the tests: real RSA keys and real signed ID-JAGs, answered through a fetch stub, so no network.
import { exportJWK, generateKeyPair, SignJWT } from "jose";

export const ISSUER = "https://idp.example.com";
export const AUDIENCE = "https://mcp.example.net/api/auth";
export const RESOURCE = "https://mcp.example.net/mcp";
export const CLIENT_ID = "client-at-receiver";

export type Route = (init: RequestInit | undefined) => Response | Promise<Response>;

export interface FakeIdp {
  routes: Map<string, Route>;
  calls: { url: string; init: RequestInit | undefined }[];
  fetch: (input: string, init?: RequestInit) => Promise<Response>;
  sign: (claims?: Record<string, unknown>, header?: Record<string, unknown>) => Promise<string>;
  metadata: Record<string, unknown>;
}

const json = (body: unknown, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json", ...headers } });
export { json };

export async function fakeIdp(): Promise<FakeIdp> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  const metadata: Record<string, unknown> = {
    issuer: ISSUER,
    jwks_uri: `${ISSUER}/jwks`,
    token_endpoint: `${ISSUER}/token`,
    identity_chaining_requested_token_types_supported: ["urn:ietf:params:oauth:token-type:id-jag"],
  };
  const routes = new Map<string, Route>([
    [`${ISSUER}/.well-known/oauth-authorization-server`, () => json(metadata)],
    [`${ISSUER}/jwks`, () => json({ keys: [jwk] })],
  ]);
  const calls: FakeIdp["calls"] = [];
  const now = Math.floor(Date.now() / 1000);
  return {
    routes,
    calls,
    metadata,
    fetch: async (input, init) => {
      calls.push({ url: input, init });
      const route = routes.get(input);
      return route ? route(init) : new Response("not found", { status: 404 });
    },
    sign: (claims = {}, header = {}) =>
      // The test's own claims come last, so they can replace any default (iss and aud included).
      new SignJWT({ iss: ISSUER, aud: AUDIENCE, iat: now, exp: now + 300, sub: "user-1234", email: "person@example.org", client_id: CLIENT_ID, jti: crypto.randomUUID(), scope: "read", resource: RESOURCE, ...claims })
        .setProtectedHeader({ alg: "RS256", typ: "oauth-id-jag+jwt", kid: "k1", ...header })
        .sign(privateKey),
  };
}

/** The INPUT_* variables the runner would set for these inputs. */
export const env = (inputs: Record<string, string>): Record<string, string> => Object.fromEntries(Object.entries(inputs).map(([k, v]) => [`INPUT_${k.replace(/ /g, "_").toUpperCase()}`, v]));

export const BASE = { issuer: ISSUER, audience: AUDIENCE, resource: RESOURCE, scopes: "read write", "client-id": CLIENT_ID };
