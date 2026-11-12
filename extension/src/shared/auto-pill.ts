// Settings of the sign-in pill that appears by itself on a recognised page (background
// auto-pill.ts), read by the worker and written by the popup. `storage.local`, never a secret:
// a switch, and the registrable domains the user asked never to see it on.

/** The pill folds away by itself this long after it appeared, untouched. */
export const AUTO_PILL_MS = 8000;
/** `storage.local`: false turns the pill off (absent or anything else: on). */
export const AUTO_PILL_KEY = "auto_pill";
/** `storage.local`: registrable domains where the pill never appears ("Never on this site"). */
export const AUTO_PILL_NEVER_KEY = "auto_pill_never";
/** The part of a storage area these settings use (`storage.local`, the popup's `storage`). */
export interface SettingsArea {
  get(keys: string | string[] | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}
const MAX_SITES = 1000;
const MAX_SITE = 253;

export interface AutoPillSettings {
  enabled: boolean;
  never: string[];
}

export function parseNeverList(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const s of raw) if (typeof s === "string" && s.length > 0 && s.length <= MAX_SITE && !out.includes(s)) out.push(s);
  return out.slice(-MAX_SITES);
}

export async function readAutoPill(area: Pick<SettingsArea, "get">): Promise<AutoPillSettings> {
  const got = await area.get([AUTO_PILL_KEY, AUTO_PILL_NEVER_KEY]);
  return { enabled: got[AUTO_PILL_KEY] !== false, never: parseNeverList(got[AUTO_PILL_NEVER_KEY]) };
}

/** Adds a registrable domain to the never-list, once. */
export async function addNever(area: SettingsArea, site: string): Promise<void> {
  const s = site.toLowerCase();
  if (s === "" || s.length > MAX_SITE) return;
  const { never } = await readAutoPill(area);
  if (never.includes(s)) return;
  await area.set({ [AUTO_PILL_NEVER_KEY]: [...never, s].slice(-MAX_SITES) });
}

/** The popup's remove button: the site may show the pill again. */
export async function removeNever(area: SettingsArea, site: string): Promise<void> {
  const { never } = await readAutoPill(area);
  await area.set({ [AUTO_PILL_NEVER_KEY]: never.filter((x) => x !== site) });
}
