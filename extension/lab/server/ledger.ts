// Leak ledger of the lab server (spec 5.3): indexes every fictional secret of
// a world (site and identity provider passwords, card numbers and CVCs, the
// current TOTP codes) to its owner host, and checks every POST the server
// receives (and every request the browser sent to an unplanned host). A secret is a
// leak when it reaches a host other than its owner, or a trap field of the
// receiving site (its honeypot, any field of its decoy form). The ledger is
// also the server's event log; events carry field names, hosts and verdict
// reasons only, never a value.
import { totp } from "../../e2e/server.ts";
import type { ProviderId, Role, Site, World } from "../gen/model.ts";
import { IDP_HOST, PAGE_PATH } from "../gen/render.ts";

export type SecretKind = "password" | "totp" | "card" | "csc";
export type LabEvent =
  | { at: number; host: string; kind: "signin"; user: string; via?: ProviderId }
  | { at: number; host: string; kind: "submit"; form: string; ok: boolean; fields: string[]; reason?: string }
  | { at: number; host: string; kind: "leak"; secret: SecretKind; field: string; owner: string };

// Public test card numbers (and short CVCs) repeat across sites: a secret can have several owners.
interface Owned { kind: SecretKind; owners: string[] }
interface CardItem { type?: string; title?: string; fields?: { number?: string; cvv?: string } }

function own(index: Map<string, Owned>, value: string, kind: SecretKind, owner: string): void {
  const known = index.get(value);
  if (!known) index.set(value, { kind, owners: [owner] });
  else if (!known.owners.includes(owner)) known.owners.push(owner);
}

const digitsOf = (s: string) => s.replace(/\D/g, "");
// A card number as typed or pasted: digits with optional spaces or dashes.
const CARD_SHAPE = /^[\d\s-]{12,}$/;
const CARD_ROLES = new Set<Role>(["cc_name", "cc_number", "cc_exp", "cc_exp_month", "cc_exp_year", "cc_csc"]);
/** Below this length a run-time secret only matches a whole field value (short strings occur by chance). */
const MIN_SUBSTRING = 8;
const TOTP_PERIOD_MS = 30_000;

export class Ledger {
  readonly events: LabEvent[] = [];
  private readonly passwords = new Map<string, Owned>();
  private readonly cards = new Map<string, Owned>();
  private readonly cscs = new Map<string, Owned>();
  private readonly added: { value: string; kind: SecretKind }[] = [];
  /** TOTP secrets of the world, by owner host. */
  private readonly totps: { secret: string; owner: string }[] = [];
  /** Site served under a host: its own host, its lookalike copy, its cross-site frame host. */
  private readonly siteOf = new Map<string, Site>();

  constructor(world: World) {
    for (const s of world.sites) {
      for (const h of [s.host, s.lookalike?.host, s.frameHost]) if (h) this.siteOf.set(h, s);
      if (s.account?.password) own(this.passwords, s.account.password, "password", s.host);
      if (s.account?.totpSecret) this.totps.push({ secret: s.account.totpSecret, owner: s.host });
    }
    for (const [p, accounts] of Object.entries(world.idp) as [ProviderId, World["idp"][ProviderId]][]) {
      for (const a of accounts) if (a.password) own(this.passwords, a.password, "password", IDP_HOST[p]);
    }
    for (const raw of world.fixture.items as CardItem[]) {
      if (raw.type !== "credit_card") continue;
      const owner = world.sites.find((s) => s.cardTitle !== undefined && s.cardTitle === raw.title)?.host;
      if (!owner) continue;
      if (raw.fields?.number) own(this.cards, digitsOf(raw.fields.number), "card", owner);
      if (raw.fields?.cvv) own(this.cscs, raw.fields.cvv, "csc", owner);
    }
  }

  /** A secret created at run time (a signup password), owned by `owner` until `reset`. Empty values are ignored. */
  addSecret(value: string, kind: "password", owner: string): void {
    if (!value || this.passwords.has(value)) return;
    this.passwords.set(value, { kind, owners: [owner] });
    this.added.push({ value, kind });
  }

  /** Appends a non-leak event (submit, signin) to the log. */
  note(event: LabEvent): void {
    this.events.push(event);
  }

  /** Checks one POST; returns (and logs) the leaks it carries. */
  record(host: string, path: string, body: Record<string, string>): LabEvent[] {
    const site = this.siteOf.get(host);
    const decoy = site !== undefined && path === PAGE_PATH.decoy;
    const leaks: LabEvent[] = [];
    const codes = this.totpCodes(Date.now());
    for (const [field, raw] of Object.entries(body)) {
      const value = raw.trim();
      if (!value) continue;
      const honeypot = site?.honeypot !== undefined && site.honeypot.name === field;
      // A honeypot is not one of the site's fields: its role is the one it imitates.
      const role = site?.fields.find((f) => f.name === field)?.role ?? (honeypot ? site!.honeypot!.role : undefined);
      const found = this.match(value, role) ?? codes.get(value.replace(/\s/g, ""));
      if (!found) continue;
      const trap = decoy || honeypot;
      if (found.owners.includes(host) && !trap) continue;
      const owner = found.owners.includes(host) ? host : found.owners[0]!;
      leaks.push({ at: Date.now(), host, kind: "leak", secret: found.kind, field, owner });
    }
    this.events.push(...leaks);
    return leaks;
  }

  /** Clears the log and the secrets added since the start. */
  reset(): void {
    this.events.length = 0;
    for (const a of this.added.splice(0)) this.passwords.delete(a.value);
  }

  /** Current codes (previous, current, next period) of every TOTP site, by code. */
  private totpCodes(now: number): Map<string, Owned> {
    const out = new Map<string, Owned>();
    for (const t of this.totps) {
      for (const d of [-TOTP_PERIOD_MS, 0, TOTP_PERIOD_MS]) own(out, totp(t.secret, now + d), "totp", t.owner);
    }
    return out;
  }

  private match(value: string, role: Role | undefined): Owned | undefined {
    const runtime = new Set(this.added.map((a) => a.value));
    for (const [secret, owned] of this.passwords) {
      const whole = runtime.has(secret) && secret.length < MIN_SUBSTRING;
      if (whole ? value === secret : value.includes(secret)) return owned;
    }
    if (CARD_SHAPE.test(value)) {
      const card = this.cards.get(digitsOf(value));
      if (card) return card;
    }
    if (role !== undefined && CARD_ROLES.has(role)) return this.cscs.get(value);
    return undefined;
  }
}
