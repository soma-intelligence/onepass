// Site-aware generation (spec 4.1, 6.3): the content script of the target
// frame reads what the page says about its new password fields, the host
// generates with the profile set in the popup (`storage.local`
// `generator_profile`), and each candidate goes back to the content script
// of that tab, which tests it against the field's HTML `pattern` with the
// browser's own RegExp. The worker never compiles nor runs a page pattern: a
// backtracking one would freeze OnePass in every tab (spec 6.3, 8). On a
// miss the host is asked again narrower (`narrow` 1: no symbols, 2:
// lowercase and digits); after three misses nothing is returned and nothing
// is filled. A tab that does not answer the check in time counts as a match
// (a dead tab never blocks generation). A refused candidate is dropped,
// never kept nor logged.
import type { Ctx, GenerationReport, Recipe } from "../bridge/client";
import { MAX_HINT, boundRules, cut, wellFormed } from "../content/password-context";
import type { BgToCs, WirePasswordContext } from "../shared/messages";
import { GENERATOR_PROFILE_KEY, type GeneratorProfile, parseGeneratorProfile } from "../shared/ui";
import type { BgExt, StorageArea } from "./ext";
import type { FillTarget } from "./fill";
import type { Session } from "./session";

/** Largest length the worker passes on (the host caps the password at 64 anyway). */
const MAX_LENGTH_ATTR = 100_000;
const NARROW_STEPS = [0, 1, 2] as const;
/** How long a tab has to answer `pattern_check` before the candidate counts as a match. */
export const PATTERN_CHECK_MS = 2000;

export interface Generated {
  password: string;
  /** Without any character of the password; null when the host sent none. */
  report: GenerationReport | null;
}

export interface GenerateDeps {
  tabs: Pick<BgExt["tabs"], "sendMessage">;
  session: Pick<Session, "request">;
  /** `storage.local`, where the popup saves the profile. */
  area: Pick<StorageArea, "get">;
  /** Bound of a `pattern_check` round trip (default `PATTERN_CHECK_MS`). */
  checkMs?: number;
}

/** The profile set in the popup; Strong when none or unreadable. */
export async function readProfile(area: Pick<StorageArea, "get">): Promise<GeneratorProfile> {
  try {
    return parseGeneratorProfile((await area.get(GENERATOR_PROFILE_KEY))[GENERATOR_PROFILE_KEY]);
  } catch {
    return "strong";
  }
}

/** The `smart` recipe for `profile`, with the page's context and the retry step when given. */
export function recipeFor(profile: GeneratorProfile, context?: WirePasswordContext, narrow = 0): Recipe {
  const recipe: Recipe =
    typeof profile === "string"
      ? { kind: "smart", profile }
      : { kind: "smart", profile: "custom", length: profile.length, symbols: profile.symbols };
  if (context) recipe.context = context;
  if (narrow === 1 || narrow === 2) recipe.narrow = narrow;
  return recipe;
}

function length(v: unknown): number | undefined {
  return typeof v === "number" && Number.isInteger(v) && v > 0 && v <= MAX_LENGTH_ATTR ? v : undefined;
}

/**
 * The content script's reply to `password_context`, rebuilt and bounded
 * again (a compromised page process could send anything): null when it is
 * not a success.
 */
export function parsePasswordContextReply(v: unknown): { context: WirePasswordContext; hasPattern: boolean } | null {
  if (typeof v !== "object" || v === null) return null;
  const o = v as Record<string, unknown>;
  if (o.ok !== true || typeof o.context !== "object" || o.context === null) return null;
  const c = o.context as Record<string, unknown>;
  const context: WirePasswordContext = { rules: Array.isArray(c.rules) ? boundRules(c.rules) : [] };
  const min = length(c.min_length);
  if (min !== undefined) context.min_length = min;
  const max = length(c.max_length);
  if (max !== undefined) context.max_length = max;
  if (typeof c.hint_text === "string") {
    const hint = cut(wellFormed(c.hint_text), MAX_HINT);
    if (hint.trim() !== "") context.hint_text = hint;
  }
  return { context, hasPattern: o.has_pattern === true };
}

/** documentId pins the exact document; frameId alone where unsupported. */
function where(t: FillTarget): { documentId: string } | { frameId: number } {
  return t.documentId !== undefined ? { documentId: t.documentId } : { frameId: t.frameId };
}

export class FormGenerator {
  constructor(private readonly deps: GenerateDeps) {}

  /** What the page of `t` says about its password fields; null when its content script does not answer. */
  private async pageContext(t: FillTarget): Promise<{ context: WirePasswordContext; hasPattern: boolean } | null> {
    const msg: BgToCs = { type: "password_context", origin: t.origin, formRef: t.formRef };
    try {
      return parsePasswordContextReply(await this.deps.tabs.sendMessage(t.tabId, msg, where(t)));
    } catch {
      return null;
    }
  }

  /**
   * The page's own verdict on `candidate` (its tab runs the pattern). No
   * answer in time, an error or a malformed reply: a match.
   */
  private async passes(t: FillTarget, candidate: string): Promise<boolean> {
    const msg: BgToCs = { type: "pattern_check", origin: t.origin, formRef: t.formRef, candidate };
    let timer: ReturnType<typeof setTimeout> | undefined;
    const late = new Promise<"late">((resolve) => {
      timer = setTimeout(() => resolve("late"), this.deps.checkMs ?? PATTERN_CHECK_MS);
    });
    try {
      const reply = await Promise.race([this.deps.tabs.sendMessage(t.tabId, msg, where(t)), late]);
      if (reply === "late" || typeof reply !== "object" || reply === null) return true;
      const r = reply as Record<string, unknown>;
      return !(r.ok === true && r.matches === false);
    } catch {
      return true;
    } finally {
      clearTimeout(timer);
    }
  }

  private async ask(ctx: Ctx, origin: string | undefined, recipe: Recipe): Promise<Generated> {
    const req: { op: "generate"; ctx: Ctx; recipe: Recipe; origin?: string } = { op: "generate", ctx, recipe };
    if (origin !== undefined) req.origin = origin;
    const g = await this.deps.session.request(req);
    return { password: g.password, report: g.report ?? null };
  }

  /**
   * A password for the new password fields of `t`: the page's rules, the
   * popup's profile, and the field's `pattern` checked with up to two
   * narrower retries. Null when the page refuses all three.
   */
  async generateForForm(t: FillTarget, ctx: Ctx): Promise<Generated | null> {
    const profile = await readProfile(this.deps.area);
    const page = await this.pageContext(t);
    for (const narrow of NARROW_STEPS) {
      const g = await this.ask(ctx, t.origin, recipeFor(profile, page?.context, narrow));
      if (!page?.hasPattern || (await this.passes(t, g.password))) return g;
      // Refused by the page: dropped, the next step asks narrower.
    }
    return null;
  }

  /** A password with the popup's profile and no page context (no form to read: the save prompt). */
  async generate(ctx: Ctx, origin?: string): Promise<Generated> {
    return this.ask(ctx, origin, recipeFor(await readProfile(this.deps.area)));
  }
}
