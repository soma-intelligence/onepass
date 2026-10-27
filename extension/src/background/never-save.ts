// "Ne jamais proposer pour <domaine>" (spec 8.5): registrable domains for
// which no save prompt is offered, in `storage.local` key `neverSave` (not a
// secret). The save flow (Task 17) consults `has` before prompting.
import type { StorageArea } from "./ext";

export const NEVER_SAVE_KEY = "neverSave";
const MAX_SITES = 1000;
const MAX_SITE = 253;

export class NeverSave {
  constructor(private readonly area: StorageArea) {}

  async list(): Promise<string[]> {
    const raw = (await this.area.get(NEVER_SAVE_KEY))[NEVER_SAVE_KEY];
    if (!Array.isArray(raw)) return [];
    return raw.filter((s): s is string => typeof s === "string" && s.length > 0 && s.length <= MAX_SITE);
  }

  async has(site: string): Promise<boolean> {
    return (await this.list()).includes(site.toLowerCase());
  }

  async add(site: string): Promise<void> {
    const s = site.toLowerCase();
    if (s === "" || s.length > MAX_SITE) return;
    const all = await this.list();
    if (all.includes(s)) return;
    all.push(s);
    await this.area.set({ [NEVER_SAVE_KEY]: all.slice(-MAX_SITES) });
  }
}
