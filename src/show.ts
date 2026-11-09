/** A value as the report shows it: short, and never more than one line (the same form as the checker's messages). */
export const show = (v: unknown): string => {
  let s: string;
  try {
    s = JSON.stringify(v) ?? String(v);
  } catch {
    s = String(v);
  }
  return s.length > 120 ? `${s.slice(0, 117)}...` : s;
};
