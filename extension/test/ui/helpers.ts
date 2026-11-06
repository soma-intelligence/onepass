import type { Timers } from "../../src/ui/components";
// Doubles for the extension pages: a scripted service worker, a clock and a
// visibility observer.
import type { UiToBg } from "../../src/shared/messages";
import type { Visibility } from "../../src/ui/components";

export const TOKEN = "AbCdEfGhIjKlMnOpQrStUv";
export const HASH = `#${TOKEN}`;

export type Reply = { ok: unknown } | { err: string };

export class FakeWorker {
  readonly sent: UiToBg[] = [];
  constructor(public answer: (m: UiToBg) => Reply | Promise<Reply>) {}
  readonly send = async (m: UiToBg): Promise<unknown> => {
    this.sent.push(structuredClone(m));
    return this.answer(m);
  };
  /** Requests the page sent, without its housekeeping (asking for relayed keys, reporting its height). */
  types(): string[] {
    return this.sent.map((m) => m.type).filter((t) => t !== "menu_keys" && !t.endsWith("_resize"));
  }
}

export class Clock {
  t = 10_000;
  readonly now = () => this.t;
  advance(ms: number): void {
    this.t += ms;
  }
}

export class FakeVisibility {
  private cbs: ((v: Visibility) => void)[] = [];
  readonly observe = (_el: Element, cb: (v: Visibility) => void) => {
    this.cbs.push(cb);
  };
  emit(v: Visibility): void {
    for (const cb of this.cbs) cb(v);
  }
}

export const flush = () => new Promise((r) => setTimeout(r, 0));

export const login = (id: string, extra: Record<string, unknown> = {}) => ({
  item_id: id,
  vault_id: "v1",
  vault_name: "Personnel",
  title: "Atlas Cloud",
  subtitle: "alex@atlas.dev",
  kind: "login",
  icon_letter: "A",
  icon_color: "#14532D",
  has_password: true,
  has_totp: false,
  methods: [],
  match: "domain",
  ...extra,
});

export function root(): HTMLElement {
  document.body.replaceChildren();
  const r = document.createElement("div");
  r.id = "root";
  document.body.appendChild(r);
  return r;
}

export const text = (el: Element) => (el.textContent ?? "").replace(/\s+/g, " ").trim();

export function button(container: Element, label: string): HTMLButtonElement {
  const all = [...container.querySelectorAll("button")];
  const b = all.find((x) => text(x) === label) ?? all.find((x) => text(x).includes(label));
  if (!b) throw new Error(`no button "${label}" in: ${text(container)}`);
  return b as HTMLButtonElement;
}

/** Timers run by hand: `runTimeouts` fires the pending timeouts, `tick` the intervals. */
export class ManualTimers implements Timers {
  private n = 0;
  readonly timeouts = new Map<number, () => void>();
  readonly intervals = new Map<number, () => void>();
  setTimeout(fn: () => void) {
    this.timeouts.set(++this.n, fn);
    return this.n;
  }
  clearTimeout(id: unknown) {
    this.timeouts.delete(id as number);
  }
  setInterval(fn: () => void) {
    this.intervals.set(++this.n, fn);
    return this.n;
  }
  clearInterval(id: unknown) {
    this.intervals.delete(id as number);
  }
  runTimeouts() {
    const fns = [...this.timeouts.values()];
    this.timeouts.clear();
    fns.forEach((f) => f());
  }
  tick() {
    [...this.intervals.values()].forEach((f) => f());
  }
}
