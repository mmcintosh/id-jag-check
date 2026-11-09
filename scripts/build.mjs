// Bundles src/main.ts into dist/index.js (what the runner runs), and writes dist/licenses.txt: the licence of every
// package the bundle contains, since their licences ask that it travel with copies. Deterministic, so CI can check
// that the committed dist/ matches the source.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { build } from "esbuild";

const result = await build({
  entryPoints: ["src/main.ts"],
  bundle: true,
  platform: "node",
  target: "node24",
  format: "esm",
  minify: true,
  legalComments: "none",
  metafile: true,
  outfile: "dist/index.js",
  logLevel: "warning",
});

const packages = new Map();
// Only packages with code in the bundle (bytesInOutput > 0): a package esbuild reads but tree-shakes away isn't copied.
for (const [input, { bytesInOutput }] of Object.entries(result.metafile.outputs["dist/index.js"].inputs)) {
  if (bytesInOutput === 0) continue;
  const at = input.lastIndexOf("node_modules/");
  if (at < 0) continue;
  const rest = input.slice(at + "node_modules/".length).split("/");
  const name = rest[0].startsWith("@") ? `${rest[0]}/${rest[1]}` : rest[0];
  packages.set(name, input.slice(0, at) + "node_modules/" + name);
}

const sections = [...packages].sort(([a], [b]) => (a < b ? -1 : 1)).map(([name, dir]) => {
  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  const file = readdirSync(dir).find((f) => /^(licen[cs]e|copying)(\.(md|txt))?$/i.test(f));
  if (!file) throw new Error(`${name} has no licence file to include`);
  return `${name}@${pkg.version} (${pkg.license})\n\n${readFileSync(join(dir, file), "utf8").trim()}\n`;
});
writeFileSync("dist/licenses.txt", `The packages bundled into dist/index.js, and their licences.\n\n${sections.join(`\n${"-".repeat(80)}\n\n`)}`);
console.log(`dist/index.js and dist/licenses.txt (${packages.size} packages: ${[...packages.keys()].sort().join(", ")})`);
