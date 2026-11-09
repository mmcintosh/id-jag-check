/** How deep a JSON value may nest before the Action refuses it: far beyond any real metadata, JWKS or token. */
export const MAX_DEPTH = 32;

/** Whether a parsed JSON value nests deeper than MAX_DEPTH. Iterative, so a hostile value can't overflow the stack. */
export function tooDeep(value: unknown, max = MAX_DEPTH): boolean {
  const stack: [unknown, number][] = [[value, 0]];
  while (stack.length > 0) {
    const [v, depth] = stack.pop() as [unknown, number];
    if (typeof v !== "object" || v === null) continue;
    if (depth >= max) return true;
    for (const x of Object.values(v)) stack.push([x, depth + 1]);
  }
  return false;
}

/** A value as the report shows it: short, and never more than one line (the same form as the checker's messages). */
export const show = (v: unknown): string => {
  let s: string;
  try {
    s = JSON.stringify(v) ?? String(v);
  } catch {
    s = "(a value that can't be shown)";
  }
  return s.length > 120 ? `${s.slice(0, 117)}...` : s;
};
