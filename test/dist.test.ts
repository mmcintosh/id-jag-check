// The committed bundle, run the way the runner runs it (node dist/index.js with GITHUB_ACTIONS=true). An input error
// stops it before any request, so this needs no network: it shows the bundle loads, reads inputs and exits non-zero.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { BASE, env } from "./idp.js";

const bundle = fileURLToPath(new URL("../dist/index.js", import.meta.url));

describe("dist/index.js", () => {
  it("runs under node as the runner starts it, masks the secrets and reports an input error", () => {
    const r = spawnSync(process.execPath, [bundle], { env: { PATH: process.env.PATH, GITHUB_ACTIONS: "true", ...env({ ...BASE, "subject-token": "bundle-secret" }) }, encoding: "utf8" });
    expect(r.status).toBe(1);
    expect(r.stdout.split("\n").filter(Boolean)).toEqual(["::add-mask::bundle-secret", "::error::The input idp-client-id is required."]);
  });
});
