// The one-click sign-in chain (spec 8.6, 8.7) as a pure state machine: no
// browser API, the clock is a parameter. The driver (driver.ts) feeds it the
// analyses of the chain's tab (origin from `sender`): the top frame's, or
// those of a child frame of exactly the top frame's origin that holds the
// sign-in form (spec C1); the navigations and load completions of the top
// frame and of the frame the last step acted in; and timer ticks. It runs
// the actions the machine returns, in the frame of the analysis.
//
// The state is plain JSON, persisted in `storage.session` by the driver. It
// holds ids, labels, hosts and times, never a secret: values are fetched
// from the host just in time by the driver for each action.
//
// Double submission: every acted step records a signature of the page (kind
// of step, host and path, fields involved) and the navigation counter of the
// page (top frame, or the frame the chain acts in). The same signature on the same navigation is a re-analysis of a
// page already handled (ignored); on a later navigation it is the same step
// coming back (password refused): `repeat`.
import { tr } from "../../shared/i18n";
import type { FillField, Summary } from "../../bridge/client";
import { parseOrigin } from "../../shared/domain";
import type { FieldRole, FormInfo, PageAnalysis, ProviderId } from "../../shared/messages";
import { PROVIDERS } from "../../shared/providers";
import { type ChainView, STOP_REASONS, type StepState, type StopReason } from "../../shared/ui";
import { titleFromSite } from "../save";

/** Spec 8.6: the whole chain must finish within 60 s of the click. */
export const DEADLINE_MS = 60_000;
/** Spec 8.6: no recognized field 4 s after the page finished loading. */
export const UNKNOWN_MS = 4_000;
/**
 * Back on the site without a sign-in form for this long: done. Never sooner
 * than `UNKNOWN_MS` after the page loaded (spec B1: its form may come late).
 */
export const DONE_SETTLE_MS = 1_500;
/** A submitted form still there, same document, after this long: refused. */
export const REPEAT_MS = 8_000;

export type ChainStatus = ChainView["status"];

export type StepKind = "fill" | "otp" | "provider_click" | "account" | "done" | "stop";

export interface ChainStep {
  kind: StepKind;
  /** Page signature the step acted on ("" for done / stop). */
  sig: string;
  /** Navigation counter of the page when the step ran. */
  nav: number;
  /** Child frame the step acted in (spec C1); absent for the top frame. */
  frameId?: number;
  at: number;
  /** Set when the step submitted its form. */
  submittedAt?: number;
  /** The submit did not reach the form (re-rendered): retried once on its copy. */
  missed?: boolean;
  /** The retry on the copy was sent: a second miss is not retried. */
  retried?: boolean;
  label: string;
  detail?: string;
  state: StepState;
}

export interface ChainPage {
  /** Navigations of the top frame, or of the frame the chain acts in, since the start. */
  nav: number;
  /** Load completed (`webNavigation.onCompleted`) at. */
  settledAt?: number;
  /** Latest analysis (the content script reports only changes) at. */
  seenAt?: number;
  /** The latest analysis showed nothing the chain can act on. */
  idle: boolean;
  /** Signature of the latest recognized analysis. */
  sig?: string;
  /** Back on the site without a form since; done after `DONE_SETTLE_MS`. */
  doneAt?: number;
}

export interface ChainState {
  v: 1;
  tabId: number;
  itemId: string;
  /** Title and username of the item, for the step labels (shown in the overlay already). */
  title: string;
  username: string;
  hasTotp: boolean;
  /** Origin the chain started on, and its registrable domain. */
  siteOrigin: string;
  site: string;
  provider?: ProviderId;
  /** The top frame committed a document on one of the provider's hosts. */
  visitedProvider?: boolean;
  /** Provider account (its own login item) and the email linked to the site. */
  account?: { itemId: string; email: string; hasTotp: boolean };
  autoSubmit: boolean;
  startedAt: number;
  deadline: number;
  status: ChainStatus;
  reason?: StopReason;
  /** Host that stopped the chain (`domain`). */
  host?: string;
  endedAt?: number;
  steps: ChainStep[];
  page: ChainPage;
}

export type ChainAction =
  | { type: "fill"; formRef: string; fields: FillField[] }
  | { type: "fill_provider"; formRef: string; fields: FillField[] }
  | { type: "click"; ref: string }
  | { type: "submit"; formRef: string }
  | { type: "stop"; reason: StopReason }
  | { type: "done" };

export interface StepResult {
  state: ChainState;
  actions: ChainAction[];
}

export interface StartParams {
  tabId: number;
  item: Summary;
  siteOrigin: string;
  /** Sign in through this provider (a method of `item`). */
  provider?: ProviderId;
  /** The provider's own login item for the linked account. */
  providerAccount?: Summary;
  /** Per item preference (R-12); true by default. */
  autoSubmit?: boolean;
  now: number;
}

const USER_ROLES: ReadonlySet<FieldRole> = new Set<FieldRole>(["username", "email"]);

const STOP_LABELS: Readonly<Record<StopReason, string>> = {
  domain: tr("Domaine non autorisé", "Domain not allowed"),
  captcha: tr("CAPTCHA détecté", "CAPTCHA detected"),
  push: tr("Validation sur le téléphone", "Approval on the phone"),
  otp: tr("Code demandé", "Code requested"),
  unknown: tr("Étape inconnue", "Unknown step"),
  timeout: tr("Délai dépassé", "Time limit reached"),
  user: tr("Arrêté", "Stopped"),
  locked: tr("OnePass verrouillé", "OnePass locked"),
  repeat: tr("Étape répétée", "Step repeated"),
};

function providerName(id: ProviderId): string {
  return PROVIDERS.find((p) => p.id === id)?.name ?? id;
}

function providerHosts(id: ProviderId | undefined): readonly string[] {
  return id ? (PROVIDERS.find((p) => p.id === id)?.hosts ?? []) : [];
}

const norm = (email: string) => email.trim().toLowerCase();

export function startChain(p: StartParams): ChainState {
  const parsed = parseOrigin(p.siteOrigin);
  const s: ChainState = {
    v: 1,
    tabId: p.tabId,
    itemId: p.item.item_id,
    title: p.item.title,
    username: p.item.subtitle,
    hasTotp: p.item.has_totp,
    siteOrigin: parsed?.origin ?? p.siteOrigin,
    site: parsed?.site ?? p.siteOrigin,
    autoSubmit: p.autoSubmit ?? true,
    startedAt: p.now,
    deadline: p.now + DEADLINE_MS,
    status: "running",
    steps: [],
    // The page the click came from is loaded already.
    page: { nav: 0, idle: true, settledAt: p.now },
  };
  if (p.provider) {
    s.provider = p.provider;
    // The chooser picks the account that will be filled: the chosen provider
    // item's email, which may differ from the method's (linked item fallback).
    const email = p.providerAccount?.subtitle ?? p.item.methods.find((m) => m.provider === p.provider)?.account_email ?? "";
    if (p.providerAccount) {
      s.account = { itemId: p.providerAccount.item_id, email: norm(email), hasTotp: p.providerAccount.has_totp };
    }
  }
  return s;
}

function clone(s: ChainState): ChainState {
  return structuredClone(s);
}

function end(s: ChainState, now: number, status: ChainStatus, step: Omit<ChainStep, "nav" | "at" | "sig">): ChainState {
  s.status = status;
  s.endedAt = now;
  s.page.doneAt = undefined;
  s.steps.push({ ...step, sig: "", nav: s.page.nav, at: now });
  return s;
}

function stopped(s: ChainState, reason: StopReason, now: number, host?: string): StepResult {
  const n = clone(s);
  n.reason = reason;
  if (host !== undefined) n.host = host;
  const st: Omit<ChainStep, "nav" | "at" | "sig"> = { kind: "stop", label: STOP_LABELS[reason], state: "stopped" };
  if (reason === "domain" && host) st.detail = host;
  if (reason === "captcha") st.detail = tr("Jamais résolu automatiquement", "Never solved automatically");
  end(n, now, reason === "user" ? "stopped" : "handoff", st);
  return { state: n, actions: [{ type: "stop", reason }] };
}

/** "Arrêter" (`user`), or a stop decided by the driver (`locked`). */
export function stopChain(s: ChainState, reason: StopReason, now: number): ChainState {
  if (s.status !== "running") return s;
  return stopped(s, reason, now).state;
}

function finished(s: ChainState, now: number): StepResult {
  const n = clone(s);
  const label = n.provider ? tr(`Retour sur ${titleFromSite(n.site)}`, `Back on ${titleFromSite(n.site)}`) : tr("Connecté", "Signed in");
  const st: Omit<ChainStep, "nav" | "at" | "sig"> = { kind: "done", label, state: "done" };
  if (n.provider) st.detail = n.site;
  end(n, now, "done", st);
  return { state: n, actions: [{ type: "done" }] };
}

/** What the page offers to the chain, before deduplication. */
type Decision =
  | { kind: "provider_click"; ref: string }
  | { kind: "account"; ref: string; email: string }
  | { kind: "otp"; form: FormInfo }
  | { kind: "fill"; form: FormInfo; fields: FillField[] }
  | { kind: "stop"; reason: StopReason };

function hasRole(f: FormInfo, roles: ReadonlySet<FieldRole> | FieldRole): boolean {
  return f.fields.some((x) => (typeof roles === "string" ? x.role === roles : roles.has(x.role)));
}

function loginForm(a: PageAnalysis): FormInfo | undefined {
  return a.forms.find((f) => (f.kind === "login" || f.kind === "otp") && (hasRole(f, USER_ROLES) || hasRole(f, "current_password")));
}

function decide(s: ChainState, a: PageAnalysis, onProvider: boolean): Decision | null {
  if (s.provider && !onProvider) {
    const b = a.providerButtons.find((x) => x.provider === s.provider);
    if (b) return { kind: "provider_click", ref: b.ref };
    // Back from the provider and the site asks to sign in again: not signed in.
    if (s.visitedProvider && loginForm(a)) return { kind: "stop", reason: "unknown" };
    // A provider chain never fills the site's own password form.
    return null;
  }
  if (onProvider && a.accountChooser.length > 0) {
    const want = s.account?.email ?? "";
    const entry = want === "" ? undefined : a.accountChooser.find((x) => norm(x.email) === want);
    return entry ? { kind: "account", ref: entry.ref, email: want } : { kind: "stop", reason: "unknown" };
  }
  const otp = a.forms.find((f) => hasRole(f, "otp"));
  if (otp) return { kind: "otp", form: otp };
  const login = loginForm(a);
  if (login) {
    const fields: FillField[] = [];
    if (hasRole(login, USER_ROLES)) fields.push("username");
    if (hasRole(login, "current_password")) fields.push("password");
    return { kind: "fill", form: login, fields };
  }
  return null;
}

function pathOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return "";
  }
}

function signature(d: Exclude<Decision, { kind: "stop" }>, host: string, url: string): string {
  const where = `${host}${pathOf(url)}`;
  switch (d.kind) {
    case "provider_click":
      return `click|${where}`;
    case "account":
      return `account|${where}|${d.email}`;
    case "otp":
      return `otp|${where}`;
    case "fill":
      return `fill|${where}|${d.fields.join(",")}`;
  }
}

function fillLabel(fields: FillField[], provider: string | null): string {
  const both = fields.includes("username") && fields.includes("password");
  if (provider) {
    if (both) return tr(`Identifiant et mot de passe ${provider} remplis`, `${provider} username and password filled`);
    return fields.includes("username") ? tr(`Identifiant ${provider} rempli`, `${provider} username filled`) : tr(`Mot de passe ${provider} rempli`, `${provider} password filled`);
  }
  if (both) return tr("Identifiant et mot de passe remplis", "Username and password filled");
  return fields.includes("username") ? tr("Identifiant rempli", "Username filled") : tr("Mot de passe rempli", "Password filled");
}

/**
 * One analysis of the chain's tab; `pageOrigin` comes from `sender`.
 * `frameId` is the frame it came from (0: top frame), recorded on the step it
 * starts so the driver follows that frame's navigations.
 */
export function step(s: ChainState, a: PageAnalysis, pageOrigin: string, now: number, frameId = 0): StepResult {
  if (s.status !== "running") return { state: s, actions: [] };
  if (now >= s.deadline) return stopped(s, "timeout", now);
  const w = where(s, pageOrigin);
  if (!w.ok) return stopped(s, "domain", now, w.host);
  const onProvider = w.onProvider;
  const host = w.host;
  if (a.captcha) return stopped(s, "captcha", now);
  if (a.push) return stopped(s, "push", now);

  const d = decide(s, a, onProvider);
  const n = clone(s);
  n.page.seenAt = now;
  if (d === null) {
    n.page.sig = undefined;
    const last = n.steps.at(-1);
    const waitingForUser = last !== undefined && last.nav === n.page.nav && last.kind === "fill" && last.submittedAt === undefined;
    const leftPage = last !== undefined && (last.nav < n.page.nav || last.submittedAt !== undefined);
    if (!onProvider && leftPage) {
      // Back on the site without a sign-in form: done, once it stays so.
      n.page.doneAt ??= now;
      n.page.idle = false;
    } else {
      n.page.doneAt = undefined;
      n.page.idle = !waitingForUser;
    }
    return { state: n, actions: [] };
  }
  n.page.doneAt = undefined;
  n.page.idle = false;
  if (d.kind === "stop") return stopped(s, d.reason, now);
  if (d.kind === "otp") {
    const hasTotp = onProvider ? (n.account?.hasTotp ?? false) : n.hasTotp;
    if (!hasTotp) return stopped(s, "otp", now);
  }

  const sig = signature(d, host, a.url);
  n.page.sig = sig;
  const prev = n.steps.find((x) => x.sig === sig);
  if (prev) {
    // Same page again: a re-analysis (same document) or the step coming back.
    if (prev.nav !== n.page.nav) return stopped(s, "repeat", now);
    // Spec B2: the page re-rendered the step's form before the submit reached
    // it. Not a repeat: submit the copy, once (no second fill).
    if (prev.missed && prev === n.steps.at(-1) && (d.kind === "fill" || d.kind === "otp") && n.autoSubmit) {
      delete prev.missed;
      prev.retried = true;
      prev.submittedAt = now;
      return { state: n, actions: [{ type: "submit", formRef: d.form.ref }] };
    }
    return { state: n, actions: [] };
  }

  const pname = onProvider && n.provider ? providerName(n.provider) : null;
  const actions: ChainAction[] = [];
  const st: ChainStep = { kind: d.kind, sig, nav: n.page.nav, at: now, label: "", state: "done" };
  if (frameId !== 0) st.frameId = frameId;
  switch (d.kind) {
    case "provider_click":
      st.label = tr(`Clic sur « Continuer avec ${providerName(n.provider ?? "google")} »`, `Clicked "Continue with ${providerName(n.provider ?? "google")}"`);
      actions.push({ type: "click", ref: d.ref });
      break;
    case "account":
      st.label = tr(`Compte choisi : ${d.email}`, `Account chosen: ${d.email}`);
      st.detail = tr(`${host} · domaine officiel vérifié`, `${host} · official domain verified`);
      actions.push({ type: "click", ref: d.ref });
      break;
    case "otp":
      st.label = pname ? tr(`Code ${pname} rempli`, `${pname} code filled`) : tr("Code à usage unique rempli", "One-time code filled");
      actions.push({ type: onProvider ? "fill_provider" : "fill", formRef: d.form.ref, fields: ["totp"] });
      break;
    case "fill":
      st.label = fillLabel(d.fields, pname);
      if (d.fields.includes("username")) st.detail = onProvider ? (n.account?.email ?? "") : n.username;
      if (st.detail === "") delete st.detail;
      actions.push({ type: onProvider ? "fill_provider" : "fill", formRef: d.form.ref, fields: d.fields });
      break;
  }
  if ((d.kind === "otp" || d.kind === "fill") && n.autoSubmit) {
    actions.push({ type: "submit", formRef: d.form.ref });
    st.submittedAt = now;
  }
  n.steps.push(st);
  return { state: n, actions };
}

/** The allowed list (R-11): the site's registrable domain, the provider's exact hosts, HTTPS only. */
function where(s: ChainState, url: string): { ok: boolean; onProvider: boolean; host: string } {
  const p = parseOrigin(url);
  const onProvider = p !== null && providerHosts(s.provider).includes(p.host);
  return { ok: p?.https === true && (onProvider || p.site === s.site), onProvider, host: p?.host ?? url.slice(0, 256) };
}

/**
 * The last step's submit did not reach its form (the content script said
 * so). The step may submit a re-rendered copy once; `submittedAt` stays, so
 * a page that does not change still ends in `repeat` after `REPEAT_MS`, and
 * a second miss (the retry) is not retried.
 */
export function submitMissed(s: ChainState): ChainState {
  const last = s.steps.at(-1);
  if (s.status !== "running" || last?.submittedAt === undefined || last.retried || last.missed) return s;
  const n = clone(s);
  const l = n.steps.at(-1);
  if (l) l.missed = true;
  return n;
}

/** A new document committed in the top frame of the chain's tab, or in the frame it acts in. */
export function navigated(s: ChainState, url: string, now: number): ChainState {
  if (s.status !== "running") return s;
  const w = where(s, url);
  if (!w.ok) return stopped(s, "domain", now, w.host).state;
  const n = clone(s);
  n.page = { nav: s.page.nav + 1, idle: true };
  if (w.onProvider) n.visitedProvider = true;
  return n;
}

/** The page finished loading (`webNavigation.onCompleted`). */
export function settled(s: ChainState, now: number): ChainState {
  if (s.status !== "running" || s.page.settledAt !== undefined) return s;
  const n = clone(s);
  n.page.settledAt = now;
  return n;
}

function lastActionAt(s: ChainState): number | undefined {
  let t: number | undefined;
  for (const x of s.steps) if (x.nav === s.page.nav && (t === undefined || x.at > t)) t = x.at;
  return t;
}

function unknownDue(s: ChainState): number | null {
  if (!s.page.idle || s.page.settledAt === undefined) return null;
  // Spec B1: a page that changed since restarts the wait (fields built late).
  return Math.max(s.page.settledAt, lastActionAt(s) ?? 0, s.page.seenAt ?? 0) + UNKNOWN_MS;
}

function doneDue(s: ChainState): number | null {
  if (s.page.doneAt === undefined) return null;
  const loaded = s.page.settledAt === undefined ? 0 : s.page.settledAt + UNKNOWN_MS;
  return Math.max(s.page.doneAt + DONE_SETTLE_MS, loaded);
}

function repeatDue(s: ChainState): number | null {
  const last = s.steps.at(-1);
  if (!last || last.submittedAt === undefined || last.nav !== s.page.nav || s.page.sig !== last.sig) return null;
  return last.submittedAt + REPEAT_MS;
}

/** Earliest time `tick` may change the state; null once the chain ended. */
export function nextDue(s: ChainState): number | null {
  if (s.status !== "running") return null;
  const dues = [s.deadline, unknownDue(s), repeatDue(s), doneDue(s)];
  return Math.min(...dues.filter((x): x is number => x !== null));
}

/** Timers: deadline, unknown page, settled done, same form still there. */
export function tick(s: ChainState, now: number): StepResult {
  if (s.status !== "running") return { state: s, actions: [] };
  if (now >= s.deadline) return stopped(s, "timeout", now);
  const d = doneDue(s);
  if (d !== null && now >= d) return finished(s, now);
  const u = unknownDue(s);
  if (u !== null && now >= u) return stopped(s, "unknown", now);
  const r = repeatDue(s);
  if (r !== null && now >= r) return stopped(s, "repeat", now);
  return { state: s, actions: [] };
}

/** What the overlay shows. */
export function chainView(s: ChainState): ChainView {
  const v: ChainView = {
    itemId: s.itemId,
    status: s.status,
    steps: s.steps.map((x) => (x.detail === undefined ? { label: x.label, state: x.state } : { label: x.label, detail: x.detail, state: x.state })),
  };
  if (s.reason !== undefined) v.reason = s.reason;
  if (s.host !== undefined) v.host = s.host;
  return v;
}

// ---- validation of a state read back from storage ----

class Bad extends Error {}
type Obj = Record<string, unknown>;

function obj(v: unknown): Obj {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Bad();
  return v as Obj;
}
function str(v: unknown, max = 4096): string {
  if (typeof v !== "string" || v.length > max) throw new Bad();
  return v;
}
function int(v: unknown): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw new Bad();
  return v;
}
function optInt(v: unknown): number | undefined {
  return v === undefined ? undefined : int(v);
}
function bool(v: unknown): boolean {
  if (typeof v !== "boolean") throw new Bad();
  return v;
}
function oneOf<T extends string>(v: unknown, all: readonly T[]): T {
  if (typeof v !== "string" || !(all as readonly string[]).includes(v)) throw new Bad();
  return v as T;
}

const STATUSES: readonly ChainStatus[] = ["running", "done", "stopped", "handoff"];
const KINDS: readonly StepKind[] = ["fill", "otp", "provider_click", "account", "done", "stop"];
const STEP_STATES: readonly StepState[] = ["pending", "active", "done", "stopped"];
const PROVIDER_IDS: readonly ProviderId[] = PROVIDERS.map((p) => p.id);

function parseStep(v: unknown): ChainStep {
  const o = obj(v);
  const st: ChainStep = {
    kind: oneOf(o.kind, KINDS),
    sig: str(o.sig, 1024),
    nav: int(o.nav),
    at: int(o.at),
    label: str(o.label, 256),
    state: oneOf(o.state, STEP_STATES),
  };
  const sub = optInt(o.submittedAt);
  if (sub !== undefined) st.submittedAt = sub;
  if (o.missed !== undefined) st.missed = bool(o.missed);
  if (o.retried !== undefined) st.retried = bool(o.retried);
  const frameId = optInt(o.frameId);
  if (frameId !== undefined && frameId > 0) st.frameId = frameId;
  if (o.detail !== undefined) st.detail = str(o.detail, 256);
  return st;
}

/** A chain state read back from `storage.session`, or null when malformed. */
export function parseChainState(raw: unknown): ChainState | null {
  try {
    const o = obj(raw);
    if (o.v !== 1) return null;
    const pg = obj(o.page);
    const page: ChainPage = { nav: int(pg.nav), idle: bool(pg.idle) };
    const settledAt = optInt(pg.settledAt);
    if (settledAt !== undefined) page.settledAt = settledAt;
    const seenAt = optInt(pg.seenAt);
    if (seenAt !== undefined) page.seenAt = seenAt;
    if (pg.sig !== undefined) page.sig = str(pg.sig, 1024);
    const doneAt = optInt(pg.doneAt);
    if (doneAt !== undefined) page.doneAt = doneAt;
    if (!Array.isArray(o.steps) || o.steps.length > 64) return null;
    const s: ChainState = {
      v: 1,
      tabId: int(o.tabId),
      itemId: str(o.itemId, 128),
      title: str(o.title, 256),
      username: str(o.username, 1024),
      hasTotp: bool(o.hasTotp),
      siteOrigin: str(o.siteOrigin, 2048),
      site: str(o.site, 253),
      autoSubmit: bool(o.autoSubmit),
      startedAt: int(o.startedAt),
      deadline: int(o.deadline),
      status: oneOf(o.status, STATUSES),
      steps: o.steps.map(parseStep),
      page,
    };
    if (o.provider !== undefined) s.provider = oneOf(o.provider, PROVIDER_IDS);
    if (o.visitedProvider !== undefined) s.visitedProvider = bool(o.visitedProvider);
    if (o.account !== undefined) {
      const a = obj(o.account);
      s.account = { itemId: str(a.itemId, 128), email: str(a.email, 320), hasTotp: bool(a.hasTotp) };
    }
    if (o.reason !== undefined) s.reason = oneOf(o.reason, STOP_REASONS);
    if (o.host !== undefined) s.host = str(o.host, 2048);
    const endedAt = optInt(o.endedAt);
    if (endedAt !== undefined) s.endedAt = endedAt;
    return s;
  } catch {
    return null;
  }
}
