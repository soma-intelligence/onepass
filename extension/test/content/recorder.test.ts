// The dev-only recorder keeps the STRUCTURE of each form step the user fills.
// A password manager must never keep a value: these tests plant values in
// every place a user can put one and look for them in the stored record.
import { beforeEach, describe, expect, it } from "vitest";
import {
  MAX_STEPS,
  RECORDER_KEY,
  appendStep,
  normalizeStep,
  readSteps,
  recordSubmit,
  type RecordedStep,
  type StepStorage,
} from "../../src/dev/recorder";
import { createRecorderContent } from "../../src/dev/recorder-content";
import { installRecorder } from "../../src/dev/recorder-bg";

const SECRETS = ["me@real.test", "hunter2", "Typed Secret Name", "4111 1111 1111 1111", "chosen-option-text", "textarea-secret", "editable-secret"];

function memoryStorage(): StepStorage & { data: Record<string, unknown>; sets: number } {
  const s = {
    data: {} as Record<string, unknown>,
    sets: 0,
    async get(key: string) {
      return key in s.data ? { [key]: structuredClone(s.data[key]) } : {};
    },
    async set(items: Record<string, unknown>) {
      s.sets++;
      Object.assign(s.data, structuredClone(items));
    },
  };
  return s;
}

describe("recordSubmit: no value ever", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("value attributes are not recorded", () => {
    document.body.innerHTML = '<form><input name="email" value="me@real.test"><input type="password" value="hunter2"></form>';
    const json = JSON.stringify(recordSubmit(document.forms[0]!, new Map()));
    expect(json).not.toContain("me@real.test");
    expect(json).not.toContain("hunter2");
  });

  it("values set after parse (typing), chosen options, textarea and contenteditable are not recorded", () => {
    document.body.innerHTML = `<div contenteditable="true">editable-secret</div>
      <form>
        <label>Name</label><input name="full" id="a">
        <input name="card" id="b">
        <select name="pick" id="c"><option value="">choose</option><option value="x">chosen-option-text</option></select>
        <textarea name="note" id="d">default text</textarea>
        <input name="pw" type="password" id="e">
      </form>`;
    const set = (id: string, v: string) => ((document.getElementById(id) as HTMLInputElement).value = v);
    set("a", "Typed Secret Name");
    set("b", "4111 1111 1111 1111");
    set("c", "x");
    set("d", "textarea-secret");
    set("e", "hunter2");
    const step = recordSubmit(document.forms[0]!, new Map());
    const json = JSON.stringify(step);
    for (const s of SECRETS) expect(json).not.toContain(s);
    // Structure is still there.
    expect(step.form.fields.map((f) => f.tag)).toEqual(["input", "input", "select", "textarea", "input"]);
  });

  it("contenteditable text next to a field is not kept as a label or neighbour", () => {
    document.body.innerHTML = '<form><div contenteditable="plaintext-only">editable-secret</div><input name="q"><span>after-editable-secret</span></form>';
    const json = JSON.stringify(recordSubmit(document.forms[0]!, new Map()));
    expect(json).not.toContain("editable-secret");
  });

  it("the page-supplied data-lab-field is dropped", () => {
    document.body.innerHTML = '<form><input name="email" data-lab-field="email"></form>';
    const step = recordSubmit(document.forms[0]!, new Map());
    expect(JSON.stringify(step)).not.toContain("lab");
    expect("lab" in step.form.fields[0]!).toBe(false);
  });

  it("keeps the host only: no path, query or port", () => {
    document.body.innerHTML = "<form><input name=a></form>";
    const step = recordSubmit(document.forms[0]!, new Map());
    expect(step.host).toBe(location.hostname);
    expect(JSON.stringify(step)).not.toContain("http");
    expect(Object.keys(step).sort()).toEqual(["at", "filled", "form", "host"]);
  });

  it("filled maps field index to the role OnePass wrote, or user", () => {
    document.body.innerHTML = '<form><input name="a" id="a"><input type="hidden" name="h"><input name="b" id="b"><input name="c" id="c"></form>';
    const filled = new Map<Element, "email" | "user">([
      [document.getElementById("a")!, "email"],
      [document.getElementById("c")!, "user"],
    ]);
    const step = recordSubmit(document.forms[0]!, filled);
    expect(step.filled).toEqual({ 0: "email", 2: "user" });
    for (const v of Object.values(step.filled)) expect(typeof v).toBe("string");
  });

  it("an element outside any form records the orphan group", () => {
    document.body.innerHTML = '<div id="spa"><input name="a" id="a"></div>';
    const step = recordSubmit(document.getElementById("spa")!, new Map([[document.getElementById("a")!, "user" as const]]));
    expect(step.form.fields).toHaveLength(1);
    expect(step.filled).toEqual({ 0: "user" });
  });
});

describe("normalizeStep", () => {
  const good = (): RecordedStep => {
    document.body.innerHTML = '<form><input name="email" autocomplete="username"></form>';
    return recordSubmit(document.forms[0]!, new Map());
  };

  it("rebuilds from known keys only, pins the host and drops lab", () => {
    const s = good() as unknown as Record<string, unknown>;
    const forged = structuredClone(s) as { form: { fields: Record<string, unknown>[] } } & Record<string, unknown>;
    forged.form.fields[0]!.lab = "email";
    forged.form.fields[0]!.value = "hunter2";
    forged.secret = "hunter2";
    const out = normalizeStep(forged, "bank.test");
    expect(out).not.toBeNull();
    expect(out!.host).toBe("bank.test");
    expect(JSON.stringify(out)).not.toContain("hunter2");
    expect(JSON.stringify(out)).not.toContain('"lab"');
  });

  it("refuses malformed input", () => {
    expect(normalizeStep(null, "a.test")).toBeNull();
    expect(normalizeStep({ form: { fields: "x" } }, "a.test")).toBeNull();
    expect(normalizeStep({ at: "now", form: { fields: [], buttons: [] }, filled: {} }, "a.test")).toBeNull();
  });
});

describe("storage", () => {
  const step = (n: number): RecordedStep => ({ host: "a.test", at: n, form: { fields: [], buttons: [] }, filled: {} });

  it("keeps one key and drops the oldest past the cap", async () => {
    const st = memoryStorage();
    st.data[RECORDER_KEY] = Array.from({ length: MAX_STEPS }, (_, i) => step(i));
    await appendStep(st, step(MAX_STEPS));
    const all = await readSteps(st);
    expect(all).toHaveLength(MAX_STEPS);
    expect(all[0]!.at).toBe(1);
    expect(all.at(-1)!.at).toBe(MAX_STEPS);
    expect(Object.keys(st.data)).toEqual([RECORDER_KEY]);
  });

  it("serializes concurrent appends", async () => {
    const st = memoryStorage();
    await Promise.all([1, 2, 3, 4, 5].map((n) => appendStep(st, step(n))));
    expect((await readSteps(st)).map((s) => s.at).sort()).toEqual([1, 2, 3, 4, 5]);
  });
});

describe("content side", () => {
  it("marks a trusted input as user, an OnePass fill by role, and sends host-only steps once", async () => {
    document.body.innerHTML = '<form id="f"><input name="a" id="a"><input name="b" id="b"></form>';
    const sent: unknown[] = [];
    const trusted = new WeakSet<Event>();
    const rec = createRecorderContent({ doc: document, send: async (m) => void sent.push(structuredClone(m)), isTrusted: (e) => trusted.has(e) });
    const a = document.getElementById("a")!;
    const e = new Event("input", { bubbles: true });
    trusted.add(e);
    a.dispatchEvent(e);
    a.dispatchEvent(new Event("input", { bubbles: true })); // untrusted: ignored
    rec.noteFilled(document.getElementById("b")!, "email");
    rec.step(document.getElementById("f")!);
    rec.step(document.getElementById("f")!); // same submit seen twice (click then submit event)
    rec.stop();
    expect(sent).toHaveLength(1);
    const m = sent[0] as { type: string; step: RecordedStep };
    expect(m.type).toBe("lab-recorder-step");
    expect(m.step.filled).toEqual({ 0: "user", 1: "email" });
  });
});

describe("background side", () => {
  const RUNTIME = { id: "extid", getURL: (p: string) => `chrome-extension://extid/${p}` };
  const wire = () => {
    const st = memoryStorage();
    let listener!: (m: unknown, s: Record<string, unknown>, r: (x?: unknown) => void) => boolean | undefined;
    installRecorder({ runtime: { ...RUNTIME, onMessage: { addListener: (l: typeof listener) => (listener = l) } }, storage: { local: st } } as never);
    const call = (m: unknown, sender: Record<string, unknown>) =>
      new Promise<unknown>((res) => {
        const handled = listener(m, sender, res);
        if (!handled) res("dropped");
      });
    return { st, call };
  };
  const cs = { id: "extid", url: "https://evil.test/login?x=1", origin: "https://bank.test", tab: { id: 1 }, frameId: 0 };
  const popup = { id: "extid", url: "chrome-extension://extid/popup.html" };
  const mk = () => {
    document.body.innerHTML = "<form><input name=a></form>";
    return recordSubmit(document.forms[0]!, new Map());
  };

  it("stores a content step under the browser-reported host and exports it to the popup only", async () => {
    const { call, st } = wire();
    await call({ type: "lab-recorder-step", step: { ...mk(), host: "forged.test" } }, cs);
    const out = (await call({ type: "lab-recorder-export" }, popup)) as { ok: { steps: RecordedStep[] } };
    expect(out.ok.steps).toHaveLength(1);
    expect(out.ok.steps[0]!.host).toBe("bank.test");
    expect(Object.keys(st.data)).toEqual([RECORDER_KEY]);
    // A web page frame or a foreign sender cannot read the record.
    expect(await call({ type: "lab-recorder-export" }, cs)).toBe("dropped");
    expect(await call({ type: "lab-recorder-export" }, { ...popup, id: "other" })).toBe("dropped");
    // An extension page cannot inject steps.
    expect(await call({ type: "lab-recorder-step", step: mk() }, popup)).toBe("dropped");
  });
});
