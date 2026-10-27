// robots.txt parser of the corpus extractor: group choice, longest match,
// wildcards, and what a fetched response means (redirect to a page: deny).
import { describe, expect, it } from "vitest";
import { isAllowed, parseRobots, robotsEntry } from "../../lab/corpus/robots.ts";

const AGENT = "OnePassLabCorpus";

describe("robots", () => {
  it("longest_match_wins", () => {
    const r = parseRobots("User-agent: *\nDisallow: /account\nAllow: /account/login\n");
    expect(isAllowed(r, AGENT, "/account/login")).toBe(true);
    expect(isAllowed(r, AGENT, "/account/settings")).toBe(false);
  });

  it("allow_beats_disallow_on_tie", () => {
    const r = parseRobots("User-agent: *\nDisallow: /login\nAllow: /login\n");
    expect(isAllowed(r, AGENT, "/login")).toBe(true);
  });

  it("agent_group_over_star", () => {
    const r = parseRobots("User-agent: *\nDisallow: /\n\nUser-agent: OnePassLabCorpus\nAllow: /\n");
    expect(isAllowed(r, AGENT, "/login")).toBe(true);
    expect(isAllowed(r, "OtherBot", "/login")).toBe(false);
  });

  it("agent_token_is_exact", () => {
    const r = parseRobots("User-agent: lab\nDisallow: /\n\nUser-agent: *\nAllow: /\n");
    expect(isAllowed(r, AGENT, "/login")).toBe(true);
    expect(isAllowed(r, "lab", "/login")).toBe(false);
  });

  it("wildcard_and_dollar", () => {
    const r = parseRobots("User-agent: *\nDisallow: /*/private\nDisallow: /exact$\n");
    expect(isAllowed(r, AGENT, "/a/private/x")).toBe(false);
    expect(isAllowed(r, AGENT, "/exact")).toBe(false);
    expect(isAllowed(r, AGENT, "/exact/more")).toBe(true);
  });

  it("empty_disallow_allows_all", () => {
    const r = parseRobots("User-agent: *\nDisallow:\n");
    expect(isAllowed(r, AGENT, "/anything")).toBe(true);
  });
  it("redirect_to_non_text_denies", () => {
    const text = () => "User-agent: *\nDisallow: /private\n";
    const r = { status: 200, ok: true, redirected: false, contentType: "text/plain; charset=utf-8" };
    expect(robotsEntry({ ...r, status: 404, ok: false }, text)).toBeNull();
    expect(robotsEntry({ ...r, status: 500, ok: false }, text)).toBe("deny");
    // Redirected to a login or home page: unreadable, not allow-all.
    expect(robotsEntry({ ...r, redirected: true, contentType: "text/html" }, () => "<html></html>")).toBe("deny");
    expect(robotsEntry({ ...r, redirected: true, contentType: "" }, () => "")).toBe("deny");
    // Redirected to a real robots.txt (another host or https): its rules apply.
    const rules = robotsEntry({ ...r, redirected: true }, text);
    expect(rules !== null && rules !== "deny" && isAllowed(rules, AGENT, "/private")).toBe(false);
  });
});
