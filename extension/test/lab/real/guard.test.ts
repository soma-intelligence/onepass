// Network guard of the real-site bench: only GET and HEAD leave, robots.txt
// for the OnePassLabReal agent, the cause of a cut, and the init script that
// cuts submits and beacons in the page.
import { describe, expect, it } from "vitest";
import { JSDOM } from "jsdom";
import { causeOf, GUARD_BINDING, GUARD_INIT_SCRIPT, GuardLog, requestVerdict, RobotsGate, type RobotsFetch, summarizeEvents } from "../../../lab/real/guard.ts";
import { HostPacer } from "../../../lab/corpus/schedule.ts";

const get = (url: string, nav = false) => ({ method: "GET", url, isMainNavigation: nav });

describe("requestVerdict", () => {
  it("lets GET and HEAD through and aborts every other method", () => {
    expect(requestVerdict(get("https://example.com/a"), true)).toBe("continue");
    expect(requestVerdict({ ...get("https://example.com/a"), method: "head" }, true)).toBe("continue");
    for (const m of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
      expect(requestVerdict({ ...get("https://example.com/a"), method: m }, true)).toBe("abort-method");
    }
  });

  it("applies robots only to top-level navigations", () => {
    expect(requestVerdict(get("https://example.com/login", true), false)).toBe("abort-robots");
    expect(requestVerdict(get("https://example.com/app.js", false), false)).toBe("continue");
  });

  it("keeps extension pages local and aborts off-list hosts of a replica run", () => {
    expect(requestVerdict({ method: "POST", url: "chrome-extension://abc/menu.html", isMainNavigation: false }, true)).toBe("continue");
    const replica = new Set(["example.com"]);
    expect(requestVerdict(get("https://example.com/"), true, replica)).toBe("continue");
    expect(requestVerdict(get("https://cdn.other.net/x.js"), true, replica)).toBe("abort-offlist");
    expect(requestVerdict({ ...get("ftp://example.com/x") }, true)).toBe("abort-offlist");
  });
});

describe("causeOf", () => {
  it("tells OnePass from the page and other extensions", () => {
    expect(causeOf("chrome-extension://onepassid/overlay.html", "onepassid")).toBe("onepass");
    expect(causeOf("chrome-extension://bitwarden/x.html", "onepassid")).toBe("other-extension");
    expect(causeOf("https://example.com/", "onepassid")).toBe("page");
    expect(causeOf(undefined, "onepassid")).toBe("unknown");
  });
});

describe("RobotsGate", () => {
  const robots = (text: string, status = 200): RobotsFetch => async () => ({ status, ok: status < 400, redirected: false, contentType: "text/plain", text });

  it("follows the OnePassLabReal group over the star group", async () => {
    const g = new RobotsGate(robots("User-agent: *\nAllow: /\n\nUser-agent: OnePassLabReal\nDisallow: /login\n"));
    expect(await g.allowed("https://example.com/login")).toBe(false);
    expect(await g.allowed("https://example.com/news")).toBe(true);
  });

  it("allows everything on a 404 and denies on an unreadable file", async () => {
    expect(await new RobotsGate(robots("", 404)).allowed("https://a.example/x")).toBe(true);
    expect(await new RobotsGate(robots("", 500)).allowed("https://a.example/x")).toBe(false);
    const failing: RobotsFetch = async () => {
      throw new Error("offline");
    };
    expect(await new RobotsGate(failing).allowed("https://a.example/x")).toBe(false);
  });

  it("fetches robots.txt once per origin", async () => {
    let calls = 0;
    const g = new RobotsGate(async () => {
      calls++;
      return { status: 200, ok: true, redirected: false, contentType: "text/plain", text: "User-agent: *\nDisallow: /private\n" };
    });
    await Promise.all([g.allowed("https://a.example/1"), g.allowed("https://a.example/private"), g.allowed("https://a.example/3")]);
    expect(calls).toBe(1);
    expect(await g.allowed("https://a.example/private/x")).toBe(false);
  });
});

describe("GuardLog", () => {
  it("returns the events of a step and summarizes them by kind and cause", () => {
    const log = new GuardLog();
    log.record({ kind: "method", host: "a.example", method: "POST", cause: "page" }, 100);
    log.record({ kind: "method", host: "a.example", method: "POST", cause: "page" }, 200);
    log.record({ kind: "method", host: "b.example", method: "POST", cause: "onepass" }, 300);
    expect(log.since(150)).toHaveLength(2);
    expect(log.since(0, (h) => h === "a.example")).toHaveLength(2);
    const s = summarizeEvents(log.events);
    expect(s).toContainEqual({ key: "method POST by page", count: 2, cause: "page", kind: "method" });
    expect(s).toContainEqual({ key: "method POST by onepass", count: 1, cause: "onepass", kind: "method" });
  });
});

describe("pacing", () => {
  it("spaces two page loads of one host by the gap", async () => {
    let now = 0;
    const waits: number[] = [];
    const pacer = new HostPacer(5000, () => now, async (ms) => {
      waits.push(ms);
      now += ms;
    });
    await pacer.wait("example.com");
    await pacer.wait("example.com");
    await pacer.wait("other.example");
    expect(waits).toEqual([5000]);
  });
});

describe("GUARD_INIT_SCRIPT", () => {
  const page = () => {
    const dom = new JSDOM(`<form action="/login" method="post"><input name="u"><button>Go</button></form>`, { runScripts: "outside-only", url: "https://example.com/" } as ConstructorParameters<typeof JSDOM>[1]);
    const reports: string[] = [];
    (dom.window as unknown as Record<string, unknown>)[GUARD_BINDING] = (k: string) => reports.push(k);
    // jsdom has no sendBeacon: give the page one, as a browser has, before the guard replaces it.
    (dom.window.Navigator.prototype as unknown as { sendBeacon: () => boolean }).sendBeacon = () => true;
    dom.window.eval(GUARD_INIT_SCRIPT);
    return { dom, reports };
  };

  it("cuts a submit event before the page's own handlers", () => {
    const { dom, reports } = page();
    const form = dom.window.document.querySelector("form")!;
    let pageSaw = false;
    form.addEventListener("submit", () => {
      pageSaw = true;
    });
    const ev = new dom.window.Event("submit", { bubbles: true, cancelable: true });
    form.dispatchEvent(ev);
    expect(ev.defaultPrevented).toBe(true);
    expect(pageSaw).toBe(false);
    expect(reports).toEqual(["submit"]);
  });

  it("cuts form.submit(), requestSubmit(), sendBeacon and window.open", () => {
    const { dom, reports } = page();
    const form = dom.window.document.querySelector("form")!;
    form.submit();
    form.requestSubmit();
    expect(dom.window.navigator.sendBeacon("https://example.com/b", "x")).toBe(false);
    expect(dom.window.open("https://example.com/pop")).toBe(null);
    expect(reports).toEqual(["form-submit", "request-submit", "beacon", "popup"]);
  });
});
