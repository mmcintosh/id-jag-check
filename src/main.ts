// The Action's entry point: mask the secrets, read the inputs, run the checks, then write the outputs, the job
// summary and the log. The step fails when any rule stops it (see fail-on), or when an input is wrong.
import { randomUUID } from "node:crypto";
import { appendFileSync } from "node:fs";
import { readInputs, SECRET_INPUTS, input } from "./inputs.js";
import { logLines, markdown } from "./report.js";
import { InputError, type RunResult, run } from "./run.js";

type Env = Record<string, string | undefined>;

/** A workflow command's data, escaped as the runner unescapes it (%, CR and LF), as @actions/core does. */
const escapeData = (s: string) => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");

/** Asks the runner to hide a value everywhere in the log (a workflow command). */
const mask = (value: string, write: (line: string) => void) => {
  for (const line of value.split(/\r?\n/)) if (line.trim()) write(`::add-mask::${escapeData(line)}`);
};

/** A multi-line output in the runner's GITHUB_OUTPUT file, with a delimiter the value can't contain. */
const outputLine = (name: string, value: string) => {
  let delimiter = `ghadelimiter_${randomUUID()}`;
  while (value.includes(delimiter)) delimiter = `ghadelimiter_${randomUUID()}`;
  return `${name}<<${delimiter}\n${value}\n${delimiter}\n`;
};

export async function main(env: Env, fetchImpl: typeof fetch, write: (line: string) => void): Promise<number> {
  for (const name of SECRET_INPUTS) {
    const v = input(env, name);
    if (v) mask(v, write);
  }
  let result: RunResult;
  try {
    result = await run(readInputs(env, Math.floor(Date.now() / 1000)), fetchImpl);
  } catch (e) {
    write(`::error::${escapeData(e instanceof InputError ? e.message : "The check stopped unexpectedly.")}`);
    return 1;
  }
  if (result.minted) mask(result.minted, write);

  for (const line of logLines(result)) write(line);
  const report = markdown(result);
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, report);
  if (env.GITHUB_OUTPUT) appendFileSync(env.GITHUB_OUTPUT, outputLine("passed", String(result.passed)) + outputLine("failed", JSON.stringify(result.failed)) + outputLine("report", report));
  if (!result.passed) write(`::error::${escapeData(`ID-JAG check failed: ${result.failed.join(", ") || "no ID-JAG to check"}.`)}`);
  return result.passed ? 0 : 1;
}

if (process.env.GITHUB_ACTIONS === "true") process.exitCode = await main(process.env, fetch, (line) => console.log(line));
