// Routes of spec 4.6 and the order of checks of spec 4.7. Per request:
// routing, bounded body read, signature headers, skew, digest (no SQL so
// far), the per-IP gate and the key lookup (one committed transaction),
// Ed25519, strict body decode, one entry point in one transaction, then the
// response. The database, Storage and the clock are injected (index.ts).
import * as proto from "./proto.ts";
import { CODES, isSqlCode, Refusal } from "./errors.ts";
import { a, type Arg, type Db, type Fn, refusalFromSqlError, type Row } from "./db.ts";
import type { Signer } from "./storage.ts";
import { clientAddress, ipKeyer, type IpSource } from "./ip.ts";
import { BadKey, type Checked, checkRequest, edVerify, importCredentialKey, verifySignature } from "./verify.ts";

/** The function's own prefix in the path the gateway hands over. */
export const PREFIX = "/mailbox";
/** Step of the rendezvous long poll. */
export const RDV_POLL_MS = 500;

export interface Deps {
  db: Db;
  signer: Signer;
  /** MAILBOX_IP_HMAC_SECRET. */
  ipSecret: Uint8Array;
  /** Where the client address is read (ip.ts). */
  ipSource: IpSource;
  /** MAILBOX_OPEN_SIGNUP=true: self-host, no invite. */
  openSignup: boolean;
  publishableKey: string | undefined;
  realtimeUrl: string | undefined;
  /** Milliseconds since the epoch. */
  now(): number;
  sleep(ms: number): Promise<void>;
}

// ----------------------------------------------------------------- helpers

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function unhex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function same(x: Uint8Array, y: Uint8Array): boolean {
  return x.length === y.length && x.every((v, i) => v === y[i]);
}

function compare(x: Uint8Array, y: Uint8Array): number {
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

const NO_STORE = { "cache-control": "no-store" };

function postcard(body: Uint8Array, status = 200): Response {
  return new Response(body as BodyInit, { status, headers: { "content-type": proto.CONTENT_TYPE, ...NO_STORE } });
}

function empty(status: number): Response {
  return new Response(null, { status, headers: NO_STORE });
}

export function errorResponse(r: Refusal): Response {
  const { status, wire } = CODES[r.code];
  const headers: Record<string, string> = { "content-type": proto.CONTENT_TYPE, ...NO_STORE };
  if (r.retryAfter !== null) headers["retry-after"] = String(r.retryAfter);
  const body = proto.encodeError({ code: wire, retry_after: r.retryAfter });
  return new Response(body as BodyInit, { status, headers });
}

/** The leading status of an in-band answer, as a refusal (null for ok). */
function inBand(row: Row | undefined): Refusal | null {
  if (!row) return new Refusal("retry");
  if (row.status === "ok") return null;
  if (isSqlCode(row.status)) {
    const ra = row.retry_after;
    return new Refusal(row.status, row.status === "rate_limited" && typeof ra === "number" ? ra : null);
  }
  return new Refusal("retry");
}

/** One SQL call in its own transaction; raised refusals mapped. */
async function call(db: Db, fn: Fn, args: Arg[]): Promise<Row[]> {
  try {
    return await db.transaction((tx) => tx.call(fn, args));
  } catch (e) {
    throw refusalFromSqlError(e);
  }
}

/** Body bytes, at most `max`: 413 as soon as more is announced or read. */
async function readBody(req: Request, max: number): Promise<Uint8Array> {
  const len = req.headers.get("content-length");
  if (len !== null && (!/^[0-9]+$/.test(len) || Number(len) > max)) throw new Refusal("too_large");
  if (!req.body) return new Uint8Array();
  const reader = req.body.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) {
      await reader.cancel().catch(() => {});
      throw new Refusal("too_large");
    }
    parts.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function decode<T, I>(f: (b: I) => T, body: I): T {
  try {
    return f(body);
  } catch {
    throw new Refusal("malformed");
  }
}

// ------------------------------------------------------------------ routes

type Auth = "none" | "signed" | "body_key";
type Query = "none" | "changes" | "wait";

interface Ctx {
  deps: Deps;
  req: Request;
  target: string;
  query: string;
  groups: string[];
  body: Uint8Array;
  /** The request's IP key, computed once (ip.ts). */
  ipKey: () => Promise<Uint8Array>;
  nowSecs: number;
  checked?: Checked;
}

interface Route {
  method: string;
  re: RegExp;
  auth: Auth;
  query: Query;
  maxBody: number;
  run: (c: Ctx) => Promise<Response>;
}

const H = "([0-9a-f]{32})";
const MB = `/v1/mailboxes/${H}`;

/** Common leading arguments of the signed entry points. */
function signedArgs(c: Ctx, mailbox: Uint8Array): Arg[] {
  const p = c.checked!.params;
  return [a.bytea(p.keyid), a.bytea(p.nonce), a.timestamptz(new Date(Number(p.created) * 1000)), a.bytea(mailbox)];
}

function requireEmpty(c: Ctx) {
  if (c.body.length !== 0) throw new Refusal("malformed");
}

/**
 * Per-IP gate and key lookup in one committed transaction, then Ed25519.
 * Returns the public key the request verified against.
 */
async function lookupKey(c: Ctx, mailbox: Uint8Array, credential: Uint8Array): Promise<Uint8Array> {
  const ipk = await c.ipKey();
  let out: { refusal: Refusal | null; key: Uint8Array | null };
  try {
    out = await c.deps.db.transaction(async (tx) => {
      const gate = inBand((await tx.call("ip_gate", [a.bytea(ipk)]))[0]);
      if (gate) return { refusal: gate, key: null };
      const rows = await tx.call("credential_key", [a.bytea(mailbox), a.bytea(credential)]);
      const r = rows[0];
      if (!r || r.status === "unknown_credential") {
        return { refusal: new Refusal("unknown_credential"), key: null };
      }
      const refused = inBand(r);
      if (refused) return { refusal: refused, key: null };
      return { refusal: null, key: r.public_key instanceof Uint8Array ? r.public_key : null };
    });
  } catch (e) {
    throw refusalFromSqlError(e);
  }
  if (out.refusal) throw out.refusal;
  if (!out.key) throw new Refusal("retry");
  return out.key;
}

/** A signed route whose key is an enrolled credential of the path mailbox. */
async function authenticate(c: Ctx, mailbox: Uint8Array) {
  const key = await lookupKey(c, mailbox, c.checked!.params.keyid);
  await verifySignature(c.checked!, key);
}

function record(r: Row) {
  return {
    seq: r.seq as bigint,
    kind: r.kind as number,
    id: r.id as Uint8Array,
    version: r.version as bigint,
    body: r.deleted
      ? null
      : r.data instanceof Uint8Array
      ? { Inline: r.data }
      : { Blob: { sha256: r.blob_sha256 as Uint8Array, size: r.size as number } },
  };
}

/** Rough postcard size of a record: its data plus a generous fixed part. */
const RECORD_OVERHEAD = 96;

async function changes(c: Ctx): Promise<Response> {
  const m = unhex(c.groups[0]);
  await authenticate(c, m);
  requireEmpty(c);
  const q = decode(proto.parseChangesQuery, c.query) as { after: bigint; limit: number; full: boolean };
  const rows = await call(c.deps.db, "api_changes", [
    ...signedArgs(c, m),
    a.bigint(q.after),
    a.integer(q.limit),
    a.boolean(q.full),
  ]);
  const refused = inBand(rows[0]);
  if (refused) throw refused;
  const first = rows[0];
  const head = first.head as bigint;
  const records = [];
  let size = 64;
  let read = 0;
  for (const r of rows) {
    if (r.seq === null || r.seq === undefined) continue;
    // Never above the head of this page (SQL bounds it too: a commit between
    // its two reads must not reach the page, which the proto would refuse).
    if ((r.seq as bigint) > head) break;
    read++;
    size += RECORD_OVERHEAD + (r.data instanceof Uint8Array ? r.data.length : 0);
    if (size > proto.PAGE_MAX_BYTES) break;
    records.push(record(r));
  }
  // A record holds 16 KiB inline at most, so the first one always fits; an
  // empty page here would end the client's fetch early, never send it.
  if (read > 0 && records.length === 0) throw new Refusal("retry");
  const last = records.length ? records[records.length - 1].seq : null;
  return postcard(proto.encodeChanges({
    incarnation: first.incarnation,
    min_cursor: first.min_cursor,
    head,
    records,
    next_after: last ?? q.after,
    more: last !== null && last < head,
  }));
}

async function info(c: Ctx): Promise<Response> {
  const m = unhex(c.groups[0]);
  await authenticate(c, m);
  requireEmpty(c);
  const rows = await call(c.deps.db, "api_mailbox_info", signedArgs(c, m));
  const refused = inBand(rows[0]);
  if (refused) throw refused;
  const r = rows[0];
  return postcard(proto.encodeInfo({
    incarnation: r.incarnation,
    wake_topic: r.wake_topic,
    min_cursor: r.min_cursor,
    limits: {
      max_bytes: r.max_bytes,
      max_records: r.max_records,
      max_credentials: r.max_credentials,
      req_per_min: r.req_per_min,
      max_commit_ops: r.max_commit_ops,
    },
    usage: { bytes: r.bytes_used, records: r.records_count, credentials: r.credentials_count },
  }));
}

async function recordRoute(c: Ctx): Promise<Response> {
  const m = unhex(c.groups[0]);
  const kind = Number(c.groups[1]);
  await authenticate(c, m);
  requireEmpty(c);
  const rows = await call(c.deps.db, "api_record", [
    ...signedArgs(c, m),
    a.smallint(kind),
    a.bytea(unhex(c.groups[2])),
  ]);
  const refused = inBand(rows[0]);
  if (refused) throw refused;
  const r = rows[0];
  return postcard(proto.encodeRecord(record({ ...r, kind, id: unhex(c.groups[2]) })));
}

async function revoke(c: Ctx): Promise<Response> {
  const m = unhex(c.groups[0]);
  await authenticate(c, m);
  requireEmpty(c);
  const rows = await call(c.deps.db, "api_revoke_credential", [...signedArgs(c, m), a.bytea(unhex(c.groups[1]))]);
  const refused = inBand(rows[0]);
  if (refused) throw refused;
  return empty(204);
}

const PUSH_KIND: Record<string, number> = { None: 0, Fcm: 1, Apns: 2, UnifiedPush: 3 };

async function setPush(c: Ctx): Promise<Response> {
  const m = unhex(c.groups[0]);
  await authenticate(c, m);
  const p = decode(proto.decodeSetPush, c.body) as { kind: string; token: Uint8Array };
  const kind = PUSH_KIND[p.kind];
  if (kind === undefined) throw new Refusal("malformed");
  const rows = await call(c.deps.db, "api_set_push", [...signedArgs(c, m), a.smallint(kind), a.bytea(p.token)]);
  const refused = inBand(rows[0]);
  if (refused) throw refused;
  return empty(204);
}

type WireBody = { Inline: Uint8Array } | { Blob: { sha256: Uint8Array; size: number } };
type WireOp = {
  kind: number;
  id: Uint8Array;
  version: bigint;
  op: "Delete" | { Put: { expected: bigint | null; body: WireBody } };
};

async function commit(c: Ctx): Promise<Response> {
  const m = unhex(c.groups[0]);
  await authenticate(c, m);
  const req = decode(proto.decodeCommit, c.body) as { ops: WireOp[] };
  const kinds: number[] = [];
  const ids: Uint8Array[] = [];
  const versions: bigint[] = [];
  const ops: number[] = [];
  const expected: (bigint | null)[] = [];
  const data: (Uint8Array | null)[] = [];
  const shas: (Uint8Array | null)[] = [];
  const sizes: (number | null)[] = [];
  for (const o of req.ops) {
    kinds.push(o.kind);
    ids.push(o.id);
    versions.push(o.version);
    if (o.op === "Delete") {
      ops.push(2);
      expected.push(null);
      data.push(null);
      shas.push(null);
      sizes.push(null);
    } else {
      const put = o.op.Put;
      ops.push(1);
      expected.push(put.expected);
      if ("Inline" in put.body) {
        data.push(put.body.Inline);
        shas.push(null);
        sizes.push(put.body.Inline.length);
      } else {
        data.push(null);
        shas.push(put.body.Blob.sha256);
        sizes.push(put.body.Blob.size);
      }
    }
  }
  const rows = await call(c.deps.db, "api_commit", [
    ...signedArgs(c, m),
    a.smallintArray(kinds),
    a.byteaArray(ids),
    a.bigintArray(versions),
    a.smallintArray(ops),
    a.bigintArray(expected),
    a.byteaArray(data),
    a.byteaArray(shas),
    a.integerArray(sizes),
  ]);
  if (rows[0]?.status === "conflict") {
    const current = rows.map((r) => ({
      kind: r.kind as number,
      id: r.id as Uint8Array,
      server: r.seq === null || r.seq === undefined ? null : record(r),
    }));
    return postcard(proto.encodeCommitResponse({ Conflict: { current } }), 409);
  }
  const refused = inBand(rows[0]);
  if (refused) throw refused;
  if (rows.length !== req.ops.length) {
    // Only a SQL bug gets here, after the batch committed: say so in the log.
    console.error("mailbox: commit applied but answered", rows.length, "rows for", req.ops.length, "operations");
    throw new Refusal("retry");
  }
  return postcard(proto.encodeCommitResponse({ Applied: { seqs: rows.map((r) => (r.seq ?? null) as bigint | null) } }));
}

/** An object name SQL returned, checked to be this mailbox's and this hash's. */
function objectName(m: Uint8Array, sha: Uint8Array, name: unknown): string {
  if (typeof name !== "string" || !new RegExp(`^${hex(m)}/${hex(sha)}\\.[1-9][0-9]{0,18}$`).test(name)) {
    throw new Refusal("retry");
  }
  return name;
}

async function blobUploads(c: Ctx): Promise<Response> {
  const m = unhex(c.groups[0]);
  await authenticate(c, m);
  const ann = decode(proto.decodeBlobAnnounce, c.body) as { blobs: [Uint8Array, number][] };
  const rows = await call(c.deps.db, "api_blob_announce", [
    ...signedArgs(c, m),
    a.byteaArray(ann.blobs.map((b) => b[0])),
    a.integerArray(ann.blobs.map((b) => b[1])),
  ]);
  const refused = inBand(rows[0]);
  if (refused) throw refused;
  const asked = new Set(ann.blobs.map((b) => hex(b[0])));
  const urls: [Uint8Array, string | null][] = [];
  for (const r of rows) {
    const sha = r.sha256 as Uint8Array;
    if (!(sha instanceof Uint8Array) || !asked.delete(hex(sha))) throw new Refusal("retry");
    const name = objectName(m, sha, r.object_name);
    urls.push([sha, r.needs_upload === true ? await c.deps.signer.upload(name) : null]);
  }
  if (asked.size !== 0) throw new Refusal("retry");
  urls.sort((x, y) => compare(x[0], y[0]));
  return postcard(proto.encodeBlobUrls({ urls }));
}

async function blobDownloads(c: Ctx): Promise<Response> {
  const m = unhex(c.groups[0]);
  await authenticate(c, m);
  const look = decode(proto.decodeBlobLookup, c.body) as { blobs: Uint8Array[] };
  const rows = await call(c.deps.db, "api_blob_lookup", [...signedArgs(c, m), a.byteaArray(look.blobs)]);
  const refused = inBand(rows[0]);
  if (refused) throw refused;
  const found = new Map<string, string>();
  for (const r of rows) {
    if (r.sha256 === null || r.sha256 === undefined) continue;
    const sha = r.sha256 as Uint8Array;
    found.set(hex(sha), objectName(m, sha, r.object_name));
  }
  const urls: [Uint8Array, string | null][] = [];
  for (const sha of look.blobs) {
    const name = found.get(hex(sha));
    urls.push([sha, name === undefined ? null : await c.deps.signer.download(name)]);
  }
  return postcard(proto.encodeBlobUrls({ urls }));
}

async function create(c: Ctx): Promise<Response> {
  const body = decode(proto.decodeCreate, c.body) as {
    public_key: Uint8Array;
    invite: Uint8Array | null;
    label: Uint8Array;
  };
  try {
    await importCredentialKey(body.public_key);
  } catch (e) {
    if (e instanceof BadKey) throw new Refusal("malformed");
    throw e;
  }
  await verifySignature(c.checked!, body.public_key);
  const p = c.checked!.params;
  const rows = await call(c.deps.db, "api_create_mailbox", [
    a.bytea(body.public_key),
    a.bytea(p.nonce),
    a.timestamptz(new Date(Number(p.created) * 1000)),
    a.bytea(body.invite),
    a.bytea(body.label),
    a.bytea(await c.ipKey()),
    a.boolean(c.deps.openSignup),
  ]);
  const refused = inBand(rows[0]);
  if (refused) throw refused;
  const r = rows[0];
  return postcard(
    proto.encodeCreated({ mailbox_id: r.mailbox_id, incarnation: r.incarnation, wake_topic: r.wake_topic }),
  );
}

interface WireTicket {
  version: number;
  mailbox_url: string;
  mailbox_id: Uint8Array;
  new_credential_pub: Uint8Array;
  expires_at: bigint;
  nonce: Uint8Array;
}

async function enroll(c: Ctx): Promise<Response> {
  const m = unhex(c.groups[0]);
  const e = decode(proto.decodeEnroll, c.body) as {
    ticket: { ticket: WireTicket; approver_credential: Uint8Array; sig: Uint8Array };
    label: Uint8Array;
  };
  const t = e.ticket.ticket;
  const key = t.new_credential_pub;
  try {
    await importCredentialKey(key);
  } catch (err) {
    if (err instanceof BadKey) throw new Refusal("malformed");
    throw err;
  }
  // The request is signed by the key the ticket lets in.
  await verifySignature(c.checked!, key);
  if (!same(t.mailbox_id, m)) throw new Refusal("malformed");
  // The deadline is SQL's to judge (expired: stale_request; more than 900 s
  // ahead: malformed); here it only has to be a time a Date can hold.
  const expires = BigInt(t.expires_at);
  if (expires < 0n || expires > BigInt(c.nowSecs) + 86_400n) throw new Refusal("malformed");

  const approverKey = await lookupKey(c, m, e.ticket.approver_credential);
  if (!(await edVerify(approverKey, proto.ticketSignedBytes(t), e.ticket.sig))) throw new Refusal("bad_signature");

  const p = c.checked!.params;
  const rows = await call(c.deps.db, "api_enroll", [
    a.bytea(key),
    a.bytea(p.nonce),
    a.timestamptz(new Date(Number(p.created) * 1000)),
    a.bytea(m),
    a.bytea(e.ticket.approver_credential),
    a.bytea(proto.ticketHash(e.ticket)),
    a.timestamptz(new Date(Number(expires) * 1000)),
    a.bytea(e.label),
    a.bytea(await c.ipKey()),
  ]);
  const refused = inBand(rows[0]);
  if (refused) throw refused;
  return empty(204);
}

function config(c: Ctx): Promise<Response> {
  const { realtimeUrl, publishableKey, openSignup } = c.deps;
  if (!realtimeUrl || !publishableKey) throw new Refusal("retry");
  return Promise.resolve(postcard(proto.encodeConfig({
    realtime_url: realtimeUrl,
    publishable_key: publishableKey,
    open_signup: openSignup,
  })));
}

function rdvArgs(c: Ctx): Arg[] {
  return [a.bytea(unhex(c.groups[0])), a.smallint(Number(c.groups[1])), a.integer(Number(c.groups[2]))];
}

async function rdvPut(c: Ctx): Promise<Response> {
  const ipk = await c.ipKey();
  const rows = await call(c.deps.db, "rdv_put", [...rdvArgs(c), a.bytea(c.body), a.bytea(ipk)]);
  if (rows[0]?.status === "conflict") return empty(409);
  const refused = inBand(rows[0]);
  if (refused) throw refused;
  return empty(204);
}

/**
 * Long poll: the IP key counts on the first call only (spec 4.9), then
 * every 500 ms until the frame is there or `wait` seconds have passed.
 */
async function rdvGet(c: Ctx): Promise<Response> {
  requireEmpty(c);
  let wait = 0;
  if (c.query !== "") {
    const w = /^wait=(0|[1-9][0-9]?)$/.exec(c.query);
    if (!w || Number(w[1]) > proto.RDV_WAIT_MAX) throw new Refusal("malformed");
    wait = Number(w[1]);
  }
  const deadline = c.deps.now() + wait * 1000;
  let ipk: Uint8Array | null = await c.ipKey();
  for (;;) {
    const rows = await call(c.deps.db, "rdv_get", [...rdvArgs(c), a.bytea(ipk)]);
    ipk = null;
    const refused = inBand(rows[0]);
    if (refused) throw refused;
    const data = rows[0].data;
    if (data instanceof Uint8Array) {
      return new Response(data as BodyInit, {
        status: 200,
        headers: { "content-type": "application/octet-stream", ...NO_STORE },
      });
    }
    if (c.deps.now() + RDV_POLL_MS > deadline) return empty(204);
    await c.deps.sleep(RDV_POLL_MS);
  }
}

async function rdvClose(c: Ctx): Promise<Response> {
  requireEmpty(c);
  const ipk = await c.ipKey();
  const rows = await call(c.deps.db, "rdv_close", [a.bytea(unhex(c.groups[0])), a.bytea(ipk)]);
  const refused = inBand(rows[0]);
  if (refused) throw refused;
  return empty(204);
}

const MAX = proto.COMMIT_BODY_MAX;
const KIND = "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?)";
const N = "(0|[1-9][0-9]{0,3})";

const ROUTES: Route[] = [
  { method: "GET", re: /^\/v1\/config$/, auth: "none", query: "none", maxBody: MAX, run: config },
  { method: "POST", re: /^\/v1\/mailboxes$/, auth: "body_key", query: "none", maxBody: MAX, run: create },
  { method: "GET", re: new RegExp(`^${MB}$`), auth: "signed", query: "none", maxBody: MAX, run: info },
  { method: "POST", re: new RegExp(`^${MB}/credentials$`), auth: "body_key", query: "none", maxBody: MAX, run: enroll },
  {
    method: "DELETE",
    re: new RegExp(`^${MB}/credentials/${H}$`),
    auth: "signed",
    query: "none",
    maxBody: MAX,
    run: revoke,
  },
  { method: "PUT", re: new RegExp(`^${MB}/push$`), auth: "signed", query: "none", maxBody: MAX, run: setPush },
  { method: "GET", re: new RegExp(`^${MB}/changes$`), auth: "signed", query: "changes", maxBody: MAX, run: changes },
  { method: "POST", re: new RegExp(`^${MB}/commit$`), auth: "signed", query: "none", maxBody: MAX, run: commit },
  {
    method: "GET",
    re: new RegExp(`^${MB}/records/${KIND}/${H}$`),
    auth: "signed",
    query: "none",
    maxBody: MAX,
    run: recordRoute,
  },
  {
    method: "POST",
    re: new RegExp(`^${MB}/blobs/uploads$`),
    auth: "signed",
    query: "none",
    maxBody: MAX,
    run: blobUploads,
  },
  {
    method: "POST",
    re: new RegExp(`^${MB}/blobs/downloads$`),
    auth: "signed",
    query: "none",
    maxBody: MAX,
    run: blobDownloads,
  },
  {
    method: "PUT",
    re: new RegExp(`^/v1/rendezvous/${H}/([01])/${N}$`),
    auth: "none",
    query: "none",
    maxBody: proto.RDV_FRAME_MAX,
    run: rdvPut,
  },
  {
    method: "GET",
    re: new RegExp(`^/v1/rendezvous/${H}/([01])/${N}$`),
    auth: "none",
    query: "wait",
    maxBody: MAX,
    run: rdvGet,
  },
  {
    method: "DELETE",
    re: new RegExp(`^/v1/rendezvous/${H}$`),
    auth: "none",
    query: "none",
    maxBody: MAX,
    run: rdvClose,
  },
];

function match(method: string, path: string): { route: Route; groups: string[] } | null {
  for (const route of ROUTES) {
    if (route.method !== method) continue;
    const m = route.re.exec(path);
    if (m) {
      // Frame numbers are below 4096.
      if (route.run === rdvPut || route.run === rdvGet) {
        if (Number(m[3]) > 4095) return null;
      }
      return { route, groups: m.slice(1) };
    }
  }
  return null;
}

/** The request handler. */
export function handler(deps: Deps): (req: Request) => Promise<Response> {
  const keyer = ipKeyer(deps.ipSecret);
  return async (req) => {
    try {
      const url = new URL(req.url);
      if (!url.pathname.startsWith(PREFIX + "/")) throw new Refusal("no_route");
      const path = url.pathname.slice(PREFIX.length);
      const found = match(req.method, path);
      if (!found) throw new Refusal("no_route");
      const { route, groups } = found;
      const query = url.search.startsWith("?") ? url.search.slice(1) : url.search;
      if (route.query === "none" && url.search !== "") throw new Refusal("malformed");
      const body = await readBody(req, route.maxBody);
      const nowSecs = Math.floor(deps.now() / 1000);
      // @onepass-target: the path after the function's prefix, then `?` and
      // the query when there is one (spec 4.7).
      const target = path + url.search;
      const address = clientAddress(req.headers, deps.ipSource);
      let key: Promise<Uint8Array> | null = null;
      const ipKey = () => (key ??= keyer(deps.now(), address));
      const ctx: Ctx = { deps, req, target, query, groups, body, ipKey, nowSecs };
      if (route.auth !== "none") {
        ctx.checked = checkRequest(req.method, target, req.headers, body, nowSecs);
      }
      return await route.run(ctx);
    } catch (e) {
      if (e instanceof Refusal) return errorResponse(e);
      console.error(
        "mailbox: unexpected failure",
        e instanceof Error ? `${e.name}: ${e.message}`.slice(0, 200) : typeof e,
      );
      return errorResponse(new Refusal("retry"));
    }
  };
}
