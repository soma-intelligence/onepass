// Leak ledger of the lab server (spec 5.3): indexes every fictional secret of
// a world (site and identity provider passwords, card numbers and CVCs) to
// its owner host, and checks every POST the server receives. A secret is a
// leak when it reaches a host other than its owner, or a trap field of the
// receiving site (its honeypot, any field of its decoy form). The ledger is
// also the server's event log; events carry field names, hosts and verdict
// reasons only, never a value.
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

export class Ledger {
  readonly events: LabEvent[] = [];
  private readonly passwords = new Map<string, Owned>();
  private readonly cards = new Map<string, Owned>();
  private readonly cscs = new Map<string, Owned>();
  private readonly added: { value: string; kind: SecretKind }[] = [];
  /** Site served under a host: its own host, its lookalike copy, its cross-site frame host. */
  private readonly siteOf = new Map<string, Site>();

  constructor(world: World) {
    for (const s of world.sites) {
      for (const h of [s.host, s.lookalike?.host, s.frameHost]) if (h) this.siteOf.set(h, s);
      if (s.account?.password) own(this.passwords, s.account.password, "password", s.host);
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
    for (const [field, raw] of Object.entries(body)) {
      const value = raw.trim();
      if (!value) continue;
      const found = this.match(value, site?.fields.find((f) => f.name === field)?.role);
      if (!found) continue;
      const trap = decoy || (site?.honeypot !== undefined && site.honeypot.name === field);
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

  private match(value: string, role: Role | undefined): Owned | undefined {
    for (const [secret, owned] of this.passwords) if (value.includes(secret)) return owned;
    if (CARD_SHAPE.test(value)) {
      const card = this.cards.get(digitsOf(value));
      if (card) return card;
    }
    if (role !== undefined && CARD_ROLES.has(role)) return this.cscs.get(value);
    return undefined;
  }
}
