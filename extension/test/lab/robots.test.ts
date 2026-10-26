// robots.txt parser of the corpus extractor: group choice, longest match, wildcards.
import { describe, expect, it } from "vitest";
import { isAllowed, parseRobots } from "../../lab/corpus/robots.ts";

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
});
