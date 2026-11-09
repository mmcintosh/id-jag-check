// The report: the job summary (Markdown) and the log lines. Both show every rule with its level, source and result,
// and the ID-JAG's header. Of its claims, only the names are shown, plus the values that identify the setup rather
// than a person (iss, aud, client_id...). sub, email and the ID-JAG itself are never shown.
import { SUPPORTED_DRAFT } from "better-auth-id-jag";
import { type RunResult, SHOWN_CLAIMS } from "./run.js";
import { show } from "./show.js";

const MARK = { pass: "✅", fail: "❌", warn: "⚠️", info: "ℹ️", skip: "⏭️" } as const;
const WORD = { pass: "pass", fail: "FAIL", warn: "warn", info: "info", skip: "skip" } as const;

/**
 * Text for the summary, inside a table cell or not: one line, and every ASCII punctuation character backslash-escaped
 * (CommonMark allows it for each), so a value from your IdP can't become a link, an image, HTML, code or a cell break.
 */
const text = (s: string) => s.replace(/[\r\n]+/g, " ").replace(/[!-/:-@[-`{-~]/g, "\\$&");

export function markdown(result: RunResult): string {
  const count = (o: keyof typeof MARK) => result.results.filter((r) => r.outcome === o).length;
  const lines: string[] = [];
  lines.push(`## ID-JAG check: ${result.passed ? "passed" : "failed"}`);
  lines.push("");
  lines.push(`${count("pass")} passed, ${count("fail")} failed, ${count("warn")} warnings, ${count("info")} notes, ${count("skip")} skipped. Checked against ${SUPPORTED_DRAFT} as better-auth-id-jag reads it.`);
  if (result.failed.length > 0) lines.push("", `Stopping the step: ${result.failed.map((id) => `\`${id}\``).join(", ")}.`);
  lines.push("", "| | Rule | Level | Source | Result |", "|---|---|---|---|---|");
  for (const r of result.results) lines.push(`| ${MARK[r.outcome]} | \`${r.id}\` | ${r.level} | ${text(r.cite)} | ${text(r.message)} |`);
  if (result.header) {
    lines.push("", "### The ID-JAG", "", "Header:", "", "```json", JSON.stringify(result.header, null, 2), "```");
  }
  if (result.claims) {
    const names = Object.keys(result.claims);
    lines.push("", `Claims: ${names.map(text).join(", ")}.`, "");
    lines.push("| Claim | Value |", "|---|---|");
    for (const name of SHOWN_CLAIMS) if (name in result.claims) lines.push(`| \`${name}\` | ${text(show(result.claims[name]))} |`);
    lines.push("", "Other claims' values (such as `sub` and `email`) aren't shown.");
  }
  return `${lines.join("\n")}\n`;
}

/** One log line per rule. A line never starts with "::", so a value can't be read as a workflow command. */
export function logLines(result: RunResult): string[] {
  return result.results.map((r) => `${WORD[r.outcome].padEnd(4)} ${r.id} (${r.level}, ${r.cite}): ${r.message.replace(/[\r\n]+/g, " ")}`);
}
