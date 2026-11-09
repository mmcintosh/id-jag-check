// The Action end to end, through main(): inputs in, log lines, outputs and job summary out, against the fake IdP.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { main } from "../src/main.js";
import { AUDIENCE, BASE, env, fakeIdp, ISSUER, json, RESOURCE } from "./idp.js";

async function runAction(inputs: Record<string, string>, idp: Awaited<ReturnType<typeof fakeIdp>>) {
  const dir = mkdtempSync(join(tmpdir(), "id-jag-check-"));
  const output = join(dir, "output");
  const summary = join(dir, "summary");
  writeFileSync(output, "");
  writeFileSync(summary, "");
  const log: string[] = [];
  const code = await main({ ...env(inputs), GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: summary }, idp.fetch as typeof fetch, (l) => log.push(l));
  const outputs: Record<string, string> = {};
  for (const m of readFileSync(output, "utf8").matchAll(/^([a-z]+)<<(ghadelimiter_[0-9a-f-]+)\n([\s\S]*?)\n\2\n/gm)) outputs[m[1] as string] = m[3] as string;
  return { code, log, outputs, summary: readFileSync(summary, "utf8") };
}

const ids = (s: string) => JSON.parse(s) as string[];

describe("an ID-JAG passed in", () => {
  it("a good ID-JAG passes: exit 0, passed=true, every rule in the summary", async () => {
    const idp = await fakeIdp();
    const r = await runAction({ ...BASE, "id-jag": await idp.sign() }, idp);
    expect(r.code).toBe(0);
    expect(r.outputs.passed).toBe("true");
    expect(ids(r.outputs.failed as string)).toEqual([]);
    for (const id of ["metadata.issuer", "jwks.keys", "signature", "claim.aud", "claim.client_id", "claim.scope", "receiver.parse"]) expect(r.summary).toContain(`\`${id}\``);
    expect(r.summary).toContain("## ID-JAG check: passed");
    expect(r.outputs.report).toBe(r.summary);
  });

  it("a wrong aud fails the step and names the rule", async () => {
    const idp = await fakeIdp();
    const r = await runAction({ ...BASE, "id-jag": await idp.sign({ aud: "https://elsewhere.example.net" }) }, idp);
    expect(r.code).toBe(1);
    expect(r.outputs.passed).toBe("false");
    expect(ids(r.outputs.failed as string)).toEqual(["claim.aud"]);
    expect(r.log.at(-1)).toBe("::error::ID-JAG check failed: claim.aud.");
  });

  it("a key the JWKS doesn't have fails the signature", async () => {
    const idp = await fakeIdp();
    const other = await fakeIdp();
    const r = await runAction({ ...BASE, "id-jag": await other.sign() }, idp);
    expect(ids(r.outputs.failed as string)).toEqual(["signature"]);
  });

  it("client_id is compared only when client-id is given", async () => {
    const idp = await fakeIdp();
    const token = await idp.sign({ client_id: "someone-else" });
    expect(ids((await runAction({ ...BASE, "id-jag": token }, idp)).outputs.failed as string)).toEqual(["claim.client_id"]);
    const { "client-id": _, ...withoutClient } = BASE;
    const r = await runAction({ ...withoutClient, "id-jag": token }, idp);
    expect(r.code).toBe(0);
    expect(r.log.some((l) => l.startsWith("skip claim.client_id"))).toBe(true);
  });

  it("fail-on: warn also stops the step on a warning", async () => {
    const idp = await fakeIdp();
    const token = await idp.sign({ email: undefined });
    expect((await runAction({ ...BASE, "id-jag": token }, idp)).code).toBe(0);
    const r = await runAction({ ...BASE, "id-jag": token, "fail-on": "warn" }, idp);
    expect(r.code).toBe(1);
    expect(ids(r.outputs.failed as string)).toEqual(["claim.email_or_aud_sub"]);
  });
});

describe("privacy: what the log and the summary never show", () => {
  it("the ID-JAG is masked first, and neither it nor sub or email appears anywhere", async () => {
    const idp = await fakeIdp();
    const token = await idp.sign({ sub: "sub-value-9f2c", email: "who@example.org" });
    const r = await runAction({ ...BASE, "id-jag": token }, idp);
    expect(r.log[0]).toBe(`::add-mask::${token}`);
    const everything = [...r.log.slice(1), r.summary, ...Object.values(r.outputs)].join("\n");
    for (const secret of [token, "sub-value-9f2c", "who@example.org"]) expect(everything).not.toContain(secret);
    // The claims' names are listed; the values shown are only the setup's own.
    expect(r.summary).toContain("`sub`");
    expect(r.summary).toContain(`| \`iss\` | \`"${ISSUER}"\` |`);
  });

  it("a value in a claim can't break the summary's table or start a workflow command", async () => {
    const idp = await fakeIdp();
    const r = await runAction({ ...BASE, "id-jag": await idp.sign({ iss: "x|y\n::warning::<b>z</b>" }) }, idp);
    expect(r.summary).not.toContain("<b>");
    expect(r.summary).not.toMatch(/\n::warning::/);
    expect(r.log.every((l) => !l.startsWith("::") || /^::(add-mask|error)::/.test(l))).toBe(true);
  });
});

describe("your metadata and keys", () => {
  it("falls back to OpenID Connect Discovery's location, with a warning", async () => {
    const idp = await fakeIdp();
    idp.routes.set(`${ISSUER}/.well-known/openid-configuration`, idp.routes.get(`${ISSUER}/.well-known/oauth-authorization-server`) as never);
    idp.routes.delete(`${ISSUER}/.well-known/oauth-authorization-server`);
    const r = await runAction({ ...BASE, "id-jag": await idp.sign() }, idp);
    expect(r.code).toBe(0);
    expect(r.log.some((l) => l.startsWith("warn metadata.location"))).toBe(true);
  });

  it("no metadata at either location: metadata.fetch fails, and the signature is skipped", async () => {
    const idp = await fakeIdp();
    idp.routes.delete(`${ISSUER}/.well-known/oauth-authorization-server`);
    const r = await runAction({ ...BASE, "id-jag": await idp.sign() }, idp);
    expect(ids(r.outputs.failed as string)).toEqual(["metadata.fetch"]);
    expect(r.log.some((l) => l.startsWith("skip signature"))).toBe(true);
  });

  it("an unreachable JWKS: jwks.fetch fails", async () => {
    const idp = await fakeIdp();
    idp.routes.delete(`${ISSUER}/jwks`);
    const r = await runAction({ ...BASE, "id-jag": await idp.sign() }, idp);
    expect(ids(r.outputs.failed as string)).toContain("jwks.fetch");
  });

  it("a redirect is never followed", async () => {
    const idp = await fakeIdp();
    idp.routes.set(`${ISSUER}/jwks`, () => new Response(null, { status: 302, headers: { location: "https://elsewhere.example.net/jwks" } }));
    const r = await runAction({ ...BASE, "id-jag": await idp.sign() }, idp);
    expect(idp.calls.map((c) => c.url)).not.toContain("https://elsewhere.example.net/jwks");
    expect(r.log.find((l) => l.includes("jwks.fetch"))).toContain("a redirect, which this Action doesn't follow");
    expect(idp.calls.every((c) => c.init?.redirect === "manual")).toBe(true);
  });

  it("a JWKS larger than the cap isn't read", async () => {
    const idp = await fakeIdp();
    idp.routes.set(`${ISSUER}/jwks`, () => new Response(new ReadableStream({ pull: (c) => c.enqueue(new Uint8Array(65_536)) }), { status: 200 }));
    const r = await runAction({ ...BASE, "id-jag": await idp.sign() }, idp);
    expect(r.log.find((l) => l.includes("jwks.fetch"))).toContain("more than 262144 bytes");
  });
});

describe("minting the ID-JAG (draft -06 section 4.3)", () => {
  const MINT = { "idp-client-id": "ci client", "idp-client-secret": "s3cret:+/=", "subject-token": "subject-token-value" };
  const tokenRoute = (idp: Awaited<ReturnType<typeof fakeIdp>>, answer: (token: string) => Response) => {
    idp.routes.set(`${ISSUER}/token`, async () => answer(await idp.sign()));
  };
  const good = (token: string) => json({ issued_token_type: "urn:ietf:params:oauth:token-type:id-jag", access_token: token, token_type: "N_A", expires_in: 300, scope: "read" }, { "cache-control": "no-store" });

  it("sends the exchange the draft describes, with Basic credentials form-encoded, and checks the answer", async () => {
    const idp = await fakeIdp();
    tokenRoute(idp, good);
    const r = await runAction({ ...BASE, ...MINT }, idp);
    expect(r.code).toBe(0);
    const call = idp.calls.find((c) => c.url === `${ISSUER}/token`);
    expect(call?.init?.method).toBe("POST");
    const form = new URLSearchParams(call?.init?.body as string);
    expect(Object.fromEntries(form)).toEqual({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      requested_token_type: "urn:ietf:params:oauth:token-type:id-jag",
      audience: AUDIENCE,
      resource: RESOURCE,
      scope: "read write",
      subject_token: "subject-token-value",
      subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
    });
    // RFC 6749 section 2.3.1: each half form-urlencoded before base64 (a space is "+", ":" is "%3A").
    expect((call?.init?.headers as Record<string, string>).authorization).toBe(`Basic ${btoa("ci+client:s3cret%3A%2B%2F%3D")}`);
    for (const id of ["exchange.response", "exchange.issued_token_type", "exchange.token_type", "exchange.cache_control", "exchange.access_token"]) expect(r.log.some((l) => l.startsWith(`pass ${id}`))).toBe(true);
  });

  it("the token endpoint comes from the metadata unless token-endpoint is given", async () => {
    const idp = await fakeIdp();
    idp.routes.set("https://other.example.com/exchange", async () => good(await idp.sign()));
    const r = await runAction({ ...BASE, ...MINT, "token-endpoint": "https://other.example.com/exchange" }, idp);
    expect(r.code).toBe(0);
    expect(idp.calls.map((c) => c.url)).not.toContain(`${ISSUER}/token`);
  });

  it("client_secret_post puts the credentials in the form instead", async () => {
    const idp = await fakeIdp();
    tokenRoute(idp, good);
    await runAction({ ...BASE, ...MINT, "idp-client-auth": "client_secret_post" }, idp);
    const call = idp.calls.find((c) => c.url === `${ISSUER}/token`);
    expect((call?.init?.headers as Record<string, string>).authorization).toBeUndefined();
    expect(new URLSearchParams(call?.init?.body as string).get("client_secret")).toBe("s3cret:+/=");
  });

  it("a wrong issued_token_type and token_type, no Cache-Control, a refresh_token: each is reported", async () => {
    const idp = await fakeIdp();
    tokenRoute(idp, (token) => json({ issued_token_type: "urn:ietf:params:oauth:token-type:jwt", access_token: token, token_type: "Bearer", refresh_token: "r" }));
    const r = await runAction({ ...BASE, ...MINT }, idp);
    expect(ids(r.outputs.failed as string)).toEqual(["exchange.issued_token_type", "exchange.token_type", "exchange.cache_control", "exchange.scope"]);
    expect(r.log.some((l) => l.startsWith("warn exchange.refresh_token"))).toBe(true);
    expect(r.log.some((l) => l.startsWith("warn exchange.expires_in"))).toBe(true);
  });

  it("no scope in the answer is fine when the ID-JAG grants exactly what was asked for", async () => {
    const idp = await fakeIdp();
    tokenRoute(idp, (token) => json({ issued_token_type: "urn:ietf:params:oauth:token-type:id-jag", access_token: token, token_type: "N_A", expires_in: 300 }, { "cache-control": "no-store" }));
    const exact = await runAction({ ...BASE, ...MINT, scopes: "read" }, idp);
    expect(exact.code).toBe(0);
    const narrowed = await runAction({ ...BASE, ...MINT }, idp);
    expect(ids(narrowed.outputs.failed as string)).toEqual(["exchange.scope"]);
  });

  it("a refusal shows the error code only, never error_description", async () => {
    const idp = await fakeIdp();
    idp.routes.set(`${ISSUER}/token`, () => new Response(JSON.stringify({ error: "invalid_grant", error_description: "user who@example.org is not assigned" }), { status: 400 }));
    const r = await runAction({ ...BASE, ...MINT }, idp);
    expect(r.code).toBe(1);
    expect(r.log.find((l) => l.includes("exchange.response"))).toContain('HTTP 400 with error "invalid_grant"');
    expect([...r.log, r.summary].join("\n")).not.toContain("who@example.org");
  });

  it("the secrets and the minted ID-JAG are masked, and none of them is printed", async () => {
    const idp = await fakeIdp();
    let minted = "";
    idp.routes.set(`${ISSUER}/token`, async () => good((minted = await idp.sign())));
    const r = await runAction({ ...BASE, ...MINT }, idp);
    expect(r.log.slice(0, 3)).toEqual(["::add-mask::subject-token-value", "::add-mask::s3cret:+/=", `::add-mask::${minted}`]);
    const printed = [...r.log.slice(3), r.summary, ...Object.values(r.outputs)].join("\n");
    for (const secret of ["subject-token-value", "s3cret:+/=", minted]) expect(printed).not.toContain(secret);
  });
});

describe("inputs", () => {
  it.each([
    [{ ...BASE }, "Give id-jag, or subject-token, idp-client-id, idp-client-secret to mint one."],
    [{ ...BASE, "id-jag": "x", "subject-token": "y" }, "Give either id-jag or the inputs to mint one (subject-token, idp-client-id, idp-client-secret), not both."],
    [{ ...BASE, "subject-token": "y" }, "The input idp-client-id is required."],
    [{ ...BASE, issuer: "http://idp.example.com", "id-jag": "x" }, "issuer must use https."],
    [{ ...BASE, scopes: " ", "id-jag": "x" }, "The input scopes is required."],
    [{ ...BASE, "fail-on": "never", "id-jag": "x" }, 'fail-on must be fail or warn; it is "never".'],
  ])("%# refuses with a message", async (inputs, message) => {
    const idp = await fakeIdp();
    const r = await runAction(inputs as Record<string, string>, idp);
    expect(r.code).toBe(1);
    expect(r.log.at(-1)).toBe(`::error::${message}`);
    expect(idp.calls).toEqual([]);
  });

  it("an input error never prints a secret", async () => {
    const idp = await fakeIdp();
    const r = await runAction({ ...BASE, "subject-token": "subject-secret", "subject-token-type": "jwt", "idp-client-id": "c", "idp-client-secret": "client-secret" }, idp);
    expect(r.log.slice(0, 2)).toEqual(["::add-mask::subject-secret", "::add-mask::client-secret"]);
    expect(r.log.slice(2).join("\n")).not.toMatch(/subject-secret|client-secret/);
  });

  it("a garbled ID-JAG is a failed rule, not a crash", async () => {
    const idp = await fakeIdp();
    const r = await runAction({ ...BASE, "id-jag": "not-a-jwt" }, idp);
    expect(ids(r.outputs.failed as string)).toEqual(["jwt.structure"]);
  });
});
