// Minimal robots.txt parser and matcher: agent group before "*", longest rule
// wins, Allow wins ties, "*" and "$" supported.

export interface RobotsRule { allow: boolean; pattern: string; }
export interface RobotsGroup { agents: string[]; rules: RobotsRule[]; }
export interface RobotsRules { groups: RobotsGroup[]; }

export function parseRobots(text: string): RobotsRules {
  const groups: RobotsGroup[] = [];
  let cur: RobotsGroup | undefined;
  let lastWasAgent = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    const i = line.indexOf(":");
    if (i < 0) continue;
    const key = line.slice(0, i).trim().toLowerCase();
    const val = line.slice(i + 1).trim();
    if (key === "user-agent") {
      if (!cur || !lastWasAgent) { cur = { agents: [], rules: [] }; groups.push(cur); }
      cur.agents.push(val.toLowerCase());
      lastWasAgent = true;
    } else if (key === "allow" || key === "disallow") {
      lastWasAgent = false;
      if (cur && val !== "") cur.rules.push({ allow: key === "allow", pattern: val });
    } else {
      lastWasAgent = false;
    }
  }
  return { groups };
}

function toRegex(pattern: string): RegExp {
  const anchored = pattern.endsWith("$");
  const body = (anchored ? pattern.slice(0, -1) : pattern)
    .split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*");
  return new RegExp("^" + body + (anchored ? "$" : ""));
}

export function isAllowed(rules: RobotsRules, agent: string, path: string): boolean {
  const a = agent.toLowerCase();
  let groups = rules.groups.filter((g) => g.agents.some((t) => t !== "*" && t !== "" && t === a));
  if (groups.length === 0) groups = rules.groups.filter((g) => g.agents.includes("*"));
  let best: RobotsRule | undefined;
  for (const g of groups) {
    for (const r of g.rules) {
      if (!toRegex(r.pattern).test(path)) continue;
      if (!best || r.pattern.length > best.pattern.length || (r.pattern.length === best.pattern.length && r.allow && !best.allow)) best = r;
    }
  }
  return best ? best.allow : true;
}

/** What a robots.txt fetch means: rules, null (no file, 404: allow all) or "deny" (unreadable). */
export type RobotsEntry = RobotsRules | null | "deny";

/**
 * The entry of a robots.txt response. A failed fetch denies; so does a file
 * redirected to anything but plain text (a login or home page is no robots.txt).
 */
export function robotsEntry(res: { status: number; ok: boolean; redirected: boolean; contentType: string }, text: () => string): RobotsEntry {
  if (res.status === 404) return null;
  if (!res.ok) return "deny";
  if (res.redirected && !res.contentType.trim().toLowerCase().startsWith("text/plain")) return "deny";
  return parseRobots(text());
}
