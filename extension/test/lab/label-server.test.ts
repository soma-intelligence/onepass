// @vitest-environment node
// Label server (Task 10): request handlers only, no browser, no socket except one bind check.
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createLabelApp, startLabelServer } from "../../lab/dataset/label-server.ts";
import { ALL_ROLES } from "../../lab/dataset/real.ts";
import type { RealDirs, RealPage } from "../../lab/dataset/real.ts";
import type { SampleField } from "../../lab/corpus/types.ts";

const f = (label: string, over: Partial<SampleField> = {}): SampleField => ({
  tag: "input", type: "text", hasPattern: false, required: true, label, visibility: "visible", role: "unknown", ...over,
});
const mk = (host: string, priv = false, fields: SampleField[] = [f("Courriel", { placeholder: "vous@exemple.fr", ariaLabel: "Adresse", before: "avant", after: "apres", name: "mail", autocomplete: "email" }), f("<b>x</b>")]): RealPage => ({
  host, n: 0, category: "login", file: `${host}.0.json`, private: priv,
  sample: { source_url: `https://${host}/`, host, category: "login", captured_at: "", extractor: 2, status: "ok", forms: [{ step: "other", fields, buttons: [] }] },
});
const tmp: string[] = [];
afterEach(() => { while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true }); });
function setup(pages: RealPage[] = [mk("a.com"), mk("b.com"), mk("rec.io", true)]) {
  const root = mkdtempSync(join(tmpdir(), "lbl-"));
  tmp.push(root);
  const d: RealDirs = { samples: join(root, "s"), private: join(root, "p"), labels: join(root, "labels"), privateLabels: join(root, "p", "labels") };
  return { d, app: createLabelApp({ pages, dirs: d }) };
}
const get = (app: ReturnType<typeof setup>["app"], url: string, host = "127.0.0.1:5000") => app.handle({ method: "GET", url, host });
const post = (app: ReturnType<typeof setup>["app"], url: string, body: string, host = "127.0.0.1:5000") => app.handle({ method: "POST", url, host, body });

describe("label server handlers", () => {
  it("redirects / to the first page without a label file", () => {
    const { app } = setup();
    expect(get(app, "/")).toMatchObject({ status: 303, headers: { location: "/p/0" } });
    post(app, "/p/0", "f0=email&go=next");
    expect(get(app, "/")).toMatchObject({ status: 303, headers: { location: "/p/1" } });
  });
  it("lists the fields in French with every role and none, progress n / total", () => {
    const { app } = setup();
    const r = get(app, "/p/0");
    expect(r.status).toBe(200);
    expect(r.headers["content-type"]).toContain("text/html");
    for (const s of ["Courriel", "vous@exemple.fr", "Adresse", "avant", "apres", "mail", "autocomplete", "1 / 3", "Suivant", "Précédent", "Enregistrer"]) expect(r.body).toContain(s);
    for (const role of [...ALL_ROLES, "none"]) expect(r.body).toContain(`value="${role}"`);
    expect(r.body).toContain("&lt;b&gt;x&lt;/b&gt;");
    expect(r.body).not.toContain("<b>x</b>");
  });
  it("makes no external request: no script, link, src or absolute URL, tight CSP", () => {
    const { app } = setup();
    const r = get(app, "/p/0");
    expect(r.body).not.toMatch(/<script|<link|\ssrc=|https?:\/\//i);
    expect(r.headers["content-security-policy"]).toContain("default-src 'none'");
  });
  it("saves the chosen roles by field index, atomically, and leaves blanks out", () => {
    const { app, d } = setup();
    const r = post(app, "/p/0", "f0=email&f1=none&go=save");
    expect(r.status).toBe(303);
    expect(r.headers.location).toBe("/p/0");
    expect(readdirSync(d.labels)).toEqual(["a.com.0.json"]);
    expect(JSON.parse(readFileSync(join(d.labels, "a.com.0.json"), "utf8"))).toEqual({ 0: "email", 1: "none" });
    post(app, "/p/0", "f0=password&f1=&go=save");
    expect(JSON.parse(readFileSync(join(d.labels, "a.com.0.json"), "utf8"))).toEqual({ 0: "password" });
  });
  it("preselects saved labels (resumable across restarts)", () => {
    const first = setup();
    post(first.app, "/p/0", "f0=email&go=save");
    const again = createLabelApp({ pages: [mk("a.com"), mk("b.com"), mk("rec.io", true)], dirs: first.d });
    expect(get(again, "/p/0").body).toMatch(/<option value="email" selected>/);
    expect(get(again, "/")).toMatchObject({ headers: { location: "/p/1" } });
  });
  it("navigates with next and previous, staying inside the range", () => {
    const { app } = setup();
    expect(post(app, "/p/0", "go=next").headers.location).toBe("/p/1");
    expect(post(app, "/p/1", "go=prev").headers.location).toBe("/p/0");
    expect(post(app, "/p/0", "go=prev").headers.location).toBe("/p/0");
    expect(post(app, "/p/2", "go=next").headers.location).toBe("/p/2");
  });
  it("writes private page labels to the private labels directory", () => {
    const { app, d } = setup();
    post(app, "/p/2", "f0=email&go=save");
    expect(existsSync(join(d.privateLabels, "rec.io.0.json"))).toBe(true);
    expect(existsSync(d.labels) ? readdirSync(d.labels) : []).toEqual([]);
  });
  it("rejects an unknown role, a bad page and a foreign Host or Origin", () => {
    const { app, d } = setup();
    expect(post(app, "/p/0", "f0=admin&go=save").status).toBe(400);
    expect(existsSync(d.labels)).toBe(false);
    expect(get(app, "/p/9").status).toBe(404);
    expect(get(app, "/p/abc").status).toBe(404);
    expect(get(app, "/p/0", "evil.example").status).toBe(403);
    expect(app.handle({ method: "POST", url: "/p/0", host: "127.0.0.1:5000", origin: "https://evil.example", body: "f0=email&go=save" }).status).toBe(403);
    expect(get(app, "/nope").status).toBe(404);
    expect(app.handle({ method: "PUT", url: "/p/0", host: "127.0.0.1:5000" }).status).toBe(405);
  });
  it("works with zero pages", () => {
    const { app } = setup([]);
    expect(get(app, "/").status).toBe(200);
    expect(get(app, "/").body).toContain("0 / 0");
  });
});

describe("startLabelServer", () => {
  it("binds 127.0.0.1 on a free port and serves the form", async () => {
    const { d } = setup();
    const srv = await startLabelServer({ pages: [mk("a.com")], dirs: d });
    try {
      expect(srv.host).toBe("127.0.0.1");
      expect(srv.port).toBeGreaterThan(0);
      const res = await fetch(`http://127.0.0.1:${srv.port}/p/0`);
      expect(res.status).toBe(200);
      expect(await res.text()).toContain("Courriel");
    } finally { await srv.close(); }
  });
});
