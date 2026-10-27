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
  types(): string[] {
    return this.sent.map((m) => m.type);
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
