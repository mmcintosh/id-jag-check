// The safety net around better-auth-id-jag's checkers: if one throws, its rule fails and the rest of the report is
// kept. None is known to throw on any input, so the checkers are replaced here by ones that do.
import { afterEach, describe, expect, it, vi } from "vitest";
import { run } from "../src/run.js";
import { AUDIENCE, CLIENT_ID, fakeIdp, ISSUER, RESOURCE } from "./idp.js";

const throwing = vi.hoisted(() => ({ metadata: false, idJag: false, exchange: false }));

vi.mock("better-auth-id-jag", async (original) => {
  const actual = await original<typeof import("better-auth-id-jag")>();
  return {
    ...actual,
    checkIssuerMetadata: (...args: Parameters<typeof actual.checkIssuerMetadata>) => {
      if (throwing.metadata) throw new Error("checker stopped");
      return actual.checkIssuerMetadata(...args);
    },
    checkExchange: (...args: Parameters<typeof actual.checkExchange>) => {
      if (throwing.exchange) throw new Error("checker stopped");
      return actual.checkExchange(...args);
    },
    checkIdJag: (...args: Parameters<typeof actual.checkIdJag>) => {
      if (throwing.idJag) throw new Error("checker stopped");
      return actual.checkIdJag(...args);
    },
  };
});

afterEach(() => {
  throwing.metadata = false;
  throwing.idJag = false;
  throwing.exchange = false;
});

const input = (token: string) => ({ issuer: ISSUER, audience: AUDIENCE, resource: RESOURCE, scopes: ["read"], clientId: CLIENT_ID, idJag: { token }, failOn: "must" as const, now: Math.floor(Date.now() / 1000) });

describe("a checker that throws", () => {
  it("checkIssuerMetadata: metadata.check fails, and the ID-JAG is still checked", async () => {
    const idp = await fakeIdp();
    throwing.metadata = true;
    const r = await run(input(await idp.sign()), idp.fetch);
    expect(r.failed).toEqual(["metadata.check"]);
    expect(r.results.some((x) => x.id === "signature" && x.outcome === "pass")).toBe(true);
  });

  it("checkIdJag: jwt.check fails, and the metadata rules are kept", async () => {
    const idp = await fakeIdp();
    throwing.idJag = true;
    const r = await run(input(await idp.sign()), idp.fetch);
    expect(r.failed).toEqual(["jwt.check"]);
    expect(r.results.some((x) => x.id === "metadata.issuer" && x.outcome === "pass")).toBe(true);
    expect(r.claims).toBeNull();
  });

  it("checkExchange: exchange.check fails, and the metadata rules are kept", async () => {
    const idp = await fakeIdp();
    idp.routes.set(`${ISSUER}/token`, async () => new Response(JSON.stringify({ access_token: await idp.sign() }), { status: 200, headers: { "content-type": "application/json" } }));
    throwing.exchange = true;
    const { idJag: _, ...rest } = input("");
    const r = await run({ ...rest, idJag: { mint: { tokenEndpoint: undefined, clientId: "c", clientSecret: "s", clientAuth: "client_secret_basic", subjectToken: "t", subjectTokenType: "id_token", audience: AUDIENCE, resource: RESOURCE, scopes: ["read"] } } }, idp.fetch);
    expect(r.failed).toEqual(["exchange.check"]);
    expect(r.results.some((x) => x.id === "metadata.issuer" && x.outcome === "pass")).toBe(true);
    expect(r.passed).toBe(false);
  });
});
