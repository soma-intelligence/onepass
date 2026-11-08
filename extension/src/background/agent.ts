// The agent channel (spec 2026-11-07-agent-browser-fill, section 5): a
// session of its own with the app, on a second native port opened with the
// stored pairing, that long-polls `agent_wait` for the jobs of an MCP agent
// the holder approved in the app.
//
// A probe reports the active tab of the front window when its top frame is
// HTTPS and of the site of the job's URL. A fill checks that tab again (same
// tab, same document, same origin), plans the top frame (`plan_fill`, ctx
// `agent`), takes the values of the job's item (`fill_login` or `fill_card`,
// ctx `agent`, which spends the request's ticket once) through the existing
// `Filler`, clicks the sign-in button for a login when asked, and reports
// the names of the fields written. Values go from the host to the content
// script only: nothing here keeps, logs or reports one.
//
// Agent fills target the top frame only, at its exact origin. A form in a
// child frame, of the same site or not, is refused (`cross_site_frame`).
//
// The port keeps the service worker alive but is no guarantee (spike
// 2026-11-07): the loop starts on every wake of the worker, and an alarm
// every 30 s reopens it when the port died.
import { wipe } from "../bridge/bytes";
import type { AgentErrorCode, AgentFilled, AgentJob, AgentProbe, Op, RequestFor, ResponseFor } from "../bridge/client";
import type { PairingRecord } from "../bridge/pairing";
import { parseOrigin } from "../shared/domain";
import type { FieldRole, PageContext, PlanGroupOut, PlanOut } from "../shared/messages";
import type { BgExt } from "./ext";
import { type FillTarget, Filler } from "./fill";
import { Frames } from "./frames";
import { loginFieldsFor } from "./planner";
import { parsePlanContextBody } from "./router";
import { type BridgeLike, RECONNECT_DELAYS_MS, toBgError } from "./session";
import type { Store } from "./store";

export type AgentError = AgentErrorCode;
export type ProbeResult = AgentProbe;
export type FillResult = AgentFilled;
export type FillJob = Extract<AgentJob, { job: "fill" }>;
export type ProbeJob = Extract<AgentJob, { job: "probe" }>;

/** The alarm that reopens the agent loop when its port died. */
export const AGENT_ALARM = "onepass-agent";
/** Period of `AGENT_ALARM` (the shortest Chromium allows). */
export const AGENT_ALARM_MINUTES = 0.5;
/** Child frames asked whether they hold the form a fill found nowhere in the top frame. */
const MAX_CHILD_FRAMES = 16;
/** Probes remembered for their fill (one request at a time per agent client, a few clients). */
const MAX_PROBES = 16;

type AgentExt = Pick<BgExt, "tabs" | "webNavigation" | "windows" | "alarms">;

export interface AgentDeps {
  ext: AgentExt;
  store: Pick<Store, "getPairing">;
  /** A client on a fresh native port (never the main session's). */
  newClient: () => BridgeLike;
  sleep?: (ms: number) => Promise<void>;
}

/** What a fill needs: the browser, the agent session, and the probes it answered. */
export interface FillDeps {
  ext: AgentExt;
  client: Pick<BridgeLike, "request">;
  /** Probes by request id: a fill must find the same tab and origin. */
  probes?: Map<number, Probed>;
}

/** A probe as the loop remembers it for the fill of the same request. */
export interface Probed {
  tabId: number;
  origin: string;
  documentId: string;
}

/**
 * The item field a written role came from: what the agent is told (the
 * item's field names, `templates.rs`), never a page role.
 */
const ITEM_FIELD: Partial<Record<FieldRole, string>> = {
  username: "username",
  email: "username",
  current_password: "password",
  otp: "totp",
  cc_name: "cardholder",
  cc_number: "number",
  cc_exp: "expiry",
  cc_exp_month: "expiry",
  cc_exp_year: "expiry",
  cc_csc: "cvv",
};

/** A login plan whose submit an agent may ask for: a sign-in page with no pay or create button. */
function submittable(plan: PlanOut): boolean {
  if (plan.intent !== "login" && plan.intent !== "otp") return false;
  return !plan.reasons.includes("pay_button") && !plan.reasons.includes("create_button");
}

/** The roles a fill of `kind` writes. */
const KIND_ROLES: Record<FillJob["kind"], ReadonlySet<FieldRole>> = {
  login: new Set<FieldRole>(["username", "email", "current_password", "otp"]),
  card: new Set<FieldRole>(["cc_name", "cc_number", "cc_exp", "cc_exp_month", "cc_exp_year", "cc_csc"]),
};

function isError(v: unknown): v is AgentError {
  return typeof v === "string";
}

/** The active tab of the front window and its top frame, as the browser reports them now. */
async function activeTop(ext: AgentExt): Promise<{ tabId: number; title: string; url: string; documentId: string | undefined } | null> {
  const windows = ext.windows;
  if (!windows) return null;
  let win: { tabs?: { id?: number; active: boolean; title?: string }[] };
  try {
    win = await windows.getLastFocused({ populate: true, windowTypes: ["normal"] });
  } catch {
    return null;
  }
  const tab = win.tabs?.find((t) => t.active);
  if (typeof tab?.id !== "number") return null;
  let frame: { url: string; documentId?: string } | null;
  try {
    frame = await ext.webNavigation.getFrame({ tabId: tab.id, frameId: 0 });
  } catch {
    return null;
  }
  if (!frame || typeof frame.url !== "string") return null;
  return { tabId: tab.id, title: typeof tab.title === "string" ? tab.title : "", url: frame.url, documentId: frame.documentId };
}

/**
 * The active tab of the front window, if its top frame is HTTPS, of the
 * registrable domain of `url`, and has a document id; else `tab_mismatch`.
 * A tab in the background never matches.
 */
export async function probeActiveTab(ext: AgentExt, url: string): Promise<ProbeResult | AgentError> {
  return (await probe(ext, url))?.result ?? "tab_mismatch";
}

async function probe(ext: AgentExt, url: string): Promise<{ result: ProbeResult; tabId: number } | null> {
  const want = parseOrigin(url);
  if (!want?.https) return null;
  const top = await activeTop(ext);
  if (!top) return null;
  const got = parseOrigin(top.url);
  // No document id (a browser without one): the fill could not pin the document.
  if (!got?.https || got.site !== want.site || typeof top.documentId !== "string" || top.documentId === "") return null;
  return { result: { tab_title: top.title, origin: got.origin, document_id: top.documentId }, tabId: top.tabId };
}

/** A host or bridge failure as an agent error code. */
function agentCode(e: unknown): AgentError {
  const code = toBgError(e).code;
  if (code === "origin_mismatch" || code === "cross_site_frame") return code;
  if (code === "insecure_origin") return "tab_mismatch";
  return "denied";
}

/** True when a page context holds a visible field a fill of `kind` writes. */
function hasKindField(forms: PageContext["forms"], kind: FillJob["kind"]): boolean {
  const roles = KIND_ROLES[kind];
  return forms.some((f) => f.fields.some((x) => x.visible && x.role !== null && roles.has(x.role)));
}

/** The page context of one frame's document, from its content script; null when it does not answer. */
async function contextOf(ext: AgentExt, tabId: number, where: { frameId?: number; documentId?: string }): Promise<PageContext["forms"] | null> {
  let reply: unknown;
  try {
    reply = await ext.tabs.sendMessage(tabId, { type: "plan_request" }, where);
  } catch {
    return null;
  }
  const ctx = (reply as { context?: unknown } | null | undefined)?.context;
  return ctx === undefined ? null : (parsePlanContextBody(ctx)?.forms ?? null);
}

/**
 * Why a fill found nothing to write in the top frame: a child frame holds a
 * form of `kind` (agent fills never reach a child frame, same site or not),
 * else no field.
 */
async function nothingInTop(ext: AgentExt, tabId: number, kind: FillJob["kind"]): Promise<AgentError> {
  let frames: { frameId: number; url: string; documentId?: string }[] | null;
  try {
    frames = await ext.webNavigation.getAllFrames({ tabId });
  } catch {
    return "no_fields";
  }
  const children = (frames ?? []).filter((f) => f.frameId !== 0 && parseOrigin(f.url)?.https === true).slice(0, MAX_CHILD_FRAMES);
  for (const f of children) {
    const forms = await contextOf(ext, tabId, f.documentId !== undefined ? { documentId: f.documentId } : { frameId: f.frameId });
    if (forms && hasKindField(forms, kind)) return "cross_site_frame";
  }
  return "no_fields";
}

/**
 * Fill the probed document with the job's item: the tab is checked again,
 * then planned, filled through `Filler` with ctx `agent`, and, for a login
 * with `submit`, its sign-in button clicked. Resolves with the names of the
 * fields written, never a value.
 */
export async function fillForAgent(deps: FillDeps, job: FillJob): Promise<FillResult | AgentError> {
  const { ext, client } = deps;
  const remembered = deps.probes?.get(job.request_id);
  deps.probes?.delete(job.request_id);
  // The same active tab, the same document, the same origin as at the probe.
  const top = await activeTop(ext);
  const origin = top ? parseOrigin(top.url) : null;
  if (!top || !origin?.https || top.documentId === undefined || top.documentId !== job.document_id) return "tab_mismatch";
  if (remembered && (remembered.tabId !== top.tabId || remembered.origin !== origin.origin || remembered.documentId !== top.documentId)) {
    return "tab_mismatch";
  }
  const tabId = top.tabId;
  const documentId = top.documentId;

  const forms = await contextOf(ext, tabId, { documentId });
  if (!forms || !hasKindField(forms, job.kind)) return nothingInTop(ext, tabId, job.kind);

  // The plan only says which form and which fields; the item is the job's, never the plan's pick.
  const context: PageContext = { origin: origin.origin, top_origin: origin.origin, frame_kind: "top", forms, typed_username_hash: null };
  let group: PlanGroupOut | undefined;
  let plan: PlanOut;
  try {
    ({ plan } = await client.request({ op: "plan_fill", ctx: "agent", agent_request: job.request_id, origin: origin.origin, context }));
    group = plan.groups.find((g) => g.kind === job.kind && g.fields.length > 0);
  } catch (e) {
    return agentCode(e);
  }
  if (!group) return nothingInTop(ext, tabId, job.kind);
  const roles = [...new Set(group.fields.map((f) => f.role))];

  // What reached the page: the roles sent (names only) and the content script's reply.
  let sentRoles: string[] = [];
  let fillReply: unknown;
  let submitReply: unknown;
  const tabs: Pick<BgExt["tabs"], "sendMessage"> = {
    sendMessage: async (id, message, options) => {
      const type = (message as { type?: unknown }).type;
      if (type === "fill") sentRoles = Object.keys((message as { values?: object }).values ?? {});
      const r = await ext.tabs.sendMessage(id, message, options);
      if (type === "fill") fillReply = r;
      if (type === "submit") submitReply = r;
      return r;
    },
  };
  // Every value request of this job carries its agent request.
  const session = {
    request: async <O extends Op>(req: RequestFor<O>): Promise<ResponseFor<O>> => {
      try {
        return await client.request({ ...req, agent_request: job.request_id } as RequestFor<O>);
      } catch (e) {
        throw toBgError(e);
      }
    },
  };
  const filler = new Filler(tabs, new Frames(ext.webNavigation), session);
  const t: FillTarget = { tabId, frameId: 0, origin: origin.origin, documentId, formRef: group.form_ref };
  try {
    if (job.kind === "login") {
      const fields = loginFieldsFor(roles);
      if (fields.length === 0) return "no_fields";
      await filler.fillLogin(t, job.item_id, fields, "agent", roles);
    } else {
      await filler.fillCard(t, job.item_id, "agent", roles);
    }
  } catch (e) {
    return agentCode(e);
  }
  const replied = (fillReply as { filled?: unknown } | null | undefined)?.filled;
  // No list in the reply: nothing is known to be written.
  const written = Array.isArray(replied) ? replied.filter((r): r is string => typeof r === "string" && sentRoles.includes(r)) : [];
  const filled = [...new Set(written.flatMap((r) => ITEM_FIELD[r as FieldRole] ?? []))];
  if (filled.length === 0) return "no_fields";

  let submitted = false;
  // A card is never submitted, nor a page that pays or creates an account.
  if (job.kind === "login" && job.submit && submittable(plan)) {
    try {
      await filler.submit(t);
      submitted = (submitReply as { ok?: unknown } | null | undefined)?.ok === true;
    } catch {
      // The page moved after the fill: the fields stay written, nothing is clicked.
    }
  }
  return { filled, submitted };
}

function wire<T>(r: T | AgentError): { ok: T } | { err: AgentError } {
  return isError(r) ? { err: r } : { ok: r };
}

function pairingKey(r: PairingRecord): string {
  return Array.from(r.pairingId, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The host no longer knows this pairing, or none is stored: the loop stops until the next wake. */
function unpaired(e: unknown): boolean {
  return toBgError(e).code === "unpaired";
}

/**
 * Run the agent session: open a client with the stored pairing, long-poll
 * `agent_wait`, answer each job. A failure reconnects after 1, 2 then 4 s;
 * past that, or without a pairing, the loop rests until the next wake (the
 * worker's start, or `AGENT_ALARM`). `stop` ends it for good.
 */
/**
 * The agent channel runs in Chromium only (v1). Firefox reports no
 * `documentId`, so every probe there would fail, and the host hands a job to
 * whichever browser polls first: a Firefox loop would take Chrome's jobs and
 * refuse them. Safari has no native port. Null where it does not run.
 */
export function startAgentLoopIfChromium(runtime: Pick<BgExt["runtime"], "getURL">, deps: AgentDeps): { stop(): void } | null {
  if (!runtime.getURL("").startsWith("chrome-extension:")) return null;
  return startAgentLoop(deps);
}

export function startAgentLoop(deps: AgentDeps): { stop(): void } {
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const probes = new Map<number, Probed>();
  let stopped = false;
  let running = false;
  let client: BridgeLike | undefined;
  let clientPairing: string | undefined;

  const drop = () => {
    client?.close();
    client = undefined;
    clientPairing = undefined;
  };

  const handle = async (c: BridgeLike, job: AgentJob): Promise<void> => {
    if (job.job === "probe") {
      const r = await probe(deps.ext, job.url);
      if (r) {
        probes.set(job.request_id, { tabId: r.tabId, origin: r.result.origin, documentId: r.result.document_id });
        while (probes.size > MAX_PROBES) probes.delete(probes.keys().next().value as number);
      }
      await c.request({ op: "agent_probe_result", request_id: job.request_id, result: wire<ProbeResult>(r ? r.result : "tab_mismatch") });
      return;
    }
    if (job.job === "fill") {
      const r = await fillForAgent({ ext: deps.ext, client: c, probes }, job);
      await c.request({ op: "agent_fill_result", request_id: job.request_id, result: wire<FillResult>(r) });
    }
  };

  const run = async (): Promise<void> => {
    if (running || stopped) return;
    running = true;
    let failures = 0;
    try {
      while (!stopped) {
        let record: PairingRecord | null;
        try {
          record = await deps.store.getPairing();
        } catch {
          record = null;
        }
        if (!record) break;
        const key = pairingKey(record);
        let c = client;
        try {
          if (!c?.isOpen || clientPairing !== key) {
            drop();
            c = deps.newClient();
            client = c;
            await c.open(record);
            clientPairing = key;
          }
        } catch (e) {
          drop();
          if (unpaired(e)) break;
          const delay = RECONNECT_DELAYS_MS[failures++];
          if (delay === undefined) break;
          await sleep(delay);
          continue;
        } finally {
          wipe(record.key);
        }
        if (stopped) break;
        try {
          const { job } = await c.request({ op: "agent_wait" });
          failures = 0;
          if (job && !stopped) await handle(c, job);
        } catch (e) {
          drop();
          if (unpaired(e)) break;
          const delay = RECONNECT_DELAYS_MS[failures++];
          if (delay === undefined) break;
          await sleep(delay);
        }
      }
    } finally {
      // Unpaired, stopped, or the host stayed away: no port is left open.
      drop();
      running = false;
    }
  };

  const alarms = deps.ext.alarms;
  if (alarms) {
    alarms.onAlarm.addListener((a) => {
      if (a.name === AGENT_ALARM) void run();
    });
    try {
      const p = alarms.create(AGENT_ALARM, { periodInMinutes: AGENT_ALARM_MINUTES });
      if (p) p.catch(() => undefined);
    } catch {
      // No alarm: the loop still starts on every wake of the worker.
    }
  }
  void run();

  return {
    stop(): void {
      stopped = true;
      drop();
      try {
        const p = alarms?.clear?.(AGENT_ALARM);
        if (p) p.catch(() => undefined);
      } catch {
        // Already gone.
      }
    },
  };
}
