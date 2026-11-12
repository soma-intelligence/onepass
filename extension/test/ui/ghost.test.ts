// The ghost page (spec 3.2): the suggested password in grey over the field, and the "Use" pill.
import { describe, expect, it } from "vitest";
import type { GhostMetrics, UiToBg } from "../../src/shared/messages";
import { t } from "../../src/shared/i18n";
import { mountGhost } from "../../src/ui/ghost";
import { Clock, FakeWorker, HASH, type Reply, TOKEN, flush, root, text } from "./helpers";

const PASSWORD = "vX7-kQ2m-Rt9z-Lp4w";
const metrics: GhostMetrics = {
  fontSize: 15,
  lineHeight: 20,
  paddingLeft: 10,
  paddingRight: 6,
  textAlign: "left",
  fontFamily: "Georgia, serif",
  box: { x: 10, y: 20, width: 240, height: 36 },
};

function setup(m: GhostMetrics = metrics, init?: Reply) {
  const r = root();
  const clock = new Clock();
  const worker = new FakeWorker((msg: UiToBg) => {
    if (msg.type === "ghost_init") return init ?? { ok: { password: PASSWORD, strength: 4, length: PASSWORD.length, metrics: m } };
    return { ok: {} };
  });
  const handle = mountGhost(r, { send: worker.send, hash: HASH, now: clock.now, trusted: () => true, observe: () => undefined });
  return { r, worker, handle, clock };
}

describe("ghost page", () => {
  it("renders the password grey with the field's font size", async () => {
    const { r, handle } = setup();
    await handle.ready;
    const pw = r.querySelector<HTMLElement>(".ghost-text")!;
    expect(pw.textContent).toBe(PASSWORD);
    expect(pw.classList.contains("mono")).toBe(false);
    const box = r.querySelector<HTMLElement>(".ghost")!;
    expect(box.style.fontSize).toBe("15px");
    expect(box.style.lineHeight).toBe("20px");
    expect(box.style.paddingLeft).toBe("10px");
    expect(box.style.paddingRight).toBe("6px");
    expect(box.style.textAlign).toBe("left");
    expect(box.style.fontFamily).toContain("Georgia");
    // The grey is the --text3 token, from theme.css.
    const css = (await import("node:fs")).readFileSync("src/ui/theme.css", "utf8");
    expect(css).toMatch(/\.ghost-text\s*\{[^}]*color:\s*var\(--text3\)/);
  });

  it("no local font: the mono face", async () => {
    const { r, handle } = setup({ ...metrics, fontFamily: null });
    await handle.ready;
    expect(r.querySelector(".ghost-text")!.classList.contains("mono")).toBe(true);
    expect(r.querySelector<HTMLElement>(".ghost")!.style.fontFamily).toBe("");
  });

  it("the pill: Use, a Tab keycap and a chevron", async () => {
    const { r, handle } = setup();
    await handle.ready;
    const pill = r.querySelector(".ghost-pill")!;
    expect(text(pill.querySelector(".ghost-use")!)).toBe(`${t("ghost.use")} ${t("ghost.tab")}`);
    expect(pill.querySelector("kbd")!.textContent).toBe(t("ghost.tab"));
    expect(pill.querySelector(".ghost-more")!.getAttribute("aria-label")).toBe(t("ghost.more"));
  });

  it("reports the pill's frame-local box, and when the pointer leaves it", async () => {
    const { r, handle, worker } = setup();
    await handle.ready;
    const pill = worker.sent.filter((m) => m.type === "ghost_pill");
    expect(pill).toHaveLength(1);
    expect(pill[0]).toMatchObject({ type: "ghost_pill", token: TOKEN, over: false });
    r.querySelector(".ghost-pill")!.dispatchEvent(new Event("pointerleave"));
    await flush();
    expect(worker.sent.filter((m) => m.type === "ghost_pill")).toHaveLength(2);
  });

  it("pill click sends ghost_accept with the token", async () => {
    const { r, handle, worker, clock } = setup();
    await handle.ready;
    // The frame click guard: nothing in the first 300 ms.
    r.querySelector<HTMLButtonElement>(".ghost-use")!.click();
    await flush();
    expect(worker.sent.some((m) => m.type === "ghost_accept")).toBe(false);
    clock.advance(300);
    r.querySelector<HTMLButtonElement>(".ghost-use")!.click();
    await flush();
    expect(worker.sent.filter((m) => m.type === "ghost_accept")).toEqual([{ type: "ghost_accept", token: TOKEN }]);
  });

  it("chevron sends ghost_menu", async () => {
    const { r, handle, worker, clock } = setup();
    await handle.ready;
    clock.advance(300);
    r.querySelector<HTMLButtonElement>(".ghost-more")!.click();
    await flush();
    expect(worker.sent.filter((m) => m.type === "ghost_menu")).toEqual([{ type: "ghost_menu", token: TOKEN }]);
    expect(worker.sent.some((m) => m.type === "ghost_accept")).toBe(false);
  });

  it("the page text never contains the token", async () => {
    const { handle } = setup();
    await handle.ready;
    expect(document.documentElement.outerHTML).not.toContain(TOKEN);
  });

  it("an expired suggestion shows nothing", async () => {
    const { r, handle } = setup(metrics, { err: "invalid" });
    await handle.ready;
    expect(r.querySelector(".ghost-text")).toBeNull();
    expect(r.querySelector(".ghost-pill")).toBeNull();
  });
});
