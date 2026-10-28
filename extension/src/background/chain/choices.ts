// Which provider account signs an item in on a site (spec 8.7): the vault may
// hold several accounts of one provider (two Google accounts, say). The menu
// and the overlay show the default one and offer the others inline; the one
// the user last picked on a site is remembered for that site and provider.
//
// The memory is `storage.local` key `signin:<site>|<provider>` holding the
// provider account's item id: no secret, like the auto-submit preference.
import type { Summary } from "../../bridge/client";
import { parseOrigin } from "../../shared/domain";
import type { ProviderId } from "../../shared/messages";
import type { ProviderChoice, SignInChoice } from "../../shared/ui";
import type { StorageArea } from "../ext";
import type { Session } from "../session";

const PREFIX = "signin:";
const ID_RE = /^[A-Za-z0-9_-]{1,128}$/;

function key(origin: string, provider: ProviderId): string | null {
  const site = parseOrigin(origin)?.site;
  return site ? `${PREFIX}${site}|${provider}` : null;
}

/** The provider account last picked for `provider` on the site of `origin`, if any. */
export async function rememberedAccount(area: StorageArea, origin: string, provider: ProviderId): Promise<string | null> {
  const k = key(origin, provider);
  if (!k) return null;
  const v = (await area.get(k))[k];
  return typeof v === "string" && ID_RE.test(v) ? v : null;
}

/** Remember the provider account a chain started with on the site of `origin`. */
export async function rememberAccount(area: StorageArea, origin: string, provider: ProviderId, accountId: string): Promise<void> {
  const k = key(origin, provider);
  if (!k || !ID_RE.test(accountId)) return;
  await area.set({ [k]: accountId });
}

const norm = (e: string) => e.trim().toLowerCase();

/**
 * The default account among `accounts` for an item's method: the one last
 * picked on this site, else the one whose email the method names, else the
 * one the host reports as linked to the site.
 */
export function defaultAccount(
  accounts: readonly Summary[],
  methodEmail: string,
  remembered: string | null,
  linked: string | undefined,
): Summary | undefined {
  return (
    (remembered ? accounts.find((a) => a.item_id === remembered) : undefined) ??
    accounts.find((a) => norm(a.subtitle) === norm(methodEmail)) ??
    (linked ? accounts.find((a) => a.item_id === linked) : undefined)
  );
}

/**
 * Sign-in choices of `items` on `origin`: one per item method, with the
 * provider's accounts (asked once per provider). A provider the host cannot
 * list (locked meanwhile) gives no choice: the method keeps its default.
 */
export async function signInChoices(
  session: Pick<Session, "request">,
  area: StorageArea,
  ctx: "menu" | "overlay",
  origin: string,
  items: readonly Summary[],
): Promise<SignInChoice[]> {
  const byProvider = new Map<ProviderId, { accounts: Summary[]; linked?: string } | null>();
  const out: SignInChoice[] = [];
  for (const it of items) {
    if (it.kind !== "login") continue;
    for (const m of it.methods) {
      if (!byProvider.has(m.provider)) {
        try {
          const r = await session.request({ op: "provider_accounts", ctx, provider: m.provider, origin });
          const accounts = Array.isArray(r.accounts) ? r.accounts : [];
          byProvider.set(m.provider, r.linked_item_id !== undefined ? { accounts, linked: r.linked_item_id } : { accounts });
        } catch {
          byProvider.set(m.provider, null);
        }
      }
      const p = byProvider.get(m.provider);
      if (!p) continue;
      const remembered = await rememberedAccount(area, origin, m.provider);
      const def = defaultAccount(p.accounts, m.account_email, remembered, p.linked);
      const accounts: ProviderChoice[] = p.accounts.map((a) => ({ itemId: a.item_id, email: a.subtitle, title: a.title }));
      const c: SignInChoice = { itemId: it.item_id, provider: m.provider, accounts };
      if (def) c.accountId = def.item_id;
      out.push(c);
    }
  }
  return out;
}
