// The database side of the edge function (spec 4.6, 4.8): one SQL entry
// point per request, as onepass_mailbox_api, through the pooler in
// transaction mode (no prepared statements). The contract with the SQL
// functions is in the header of migration 20261031120100:
//
// - a raised refusal (SQLSTATE 'OP' || <HTTP status>, message = the snake
//   case code, retry_after in DETAIL) rolls the transaction back;
// - every other outcome is in band (leading columns status, retry_after) and
//   the transaction COMMITS, so the nonce and the counters stick;
// - any other SQLSTATE is a bug or a transient fault: 503 retry.
import postgres from "postgres";
import { CODES, isSqlCode, Refusal } from "./errors.ts";

export type Row = Record<string, unknown>;

export type SqlType =
  | "bytea"
  | "smallint"
  | "integer"
  | "bigint"
  | "boolean"
  | "timestamptz"
  | "bytea[]"
  | "smallint[]"
  | "integer[]"
  | "bigint[]";

export interface Arg {
  value: Uint8Array | number | bigint | boolean | Date | null | (Uint8Array | number | bigint | null)[];
  type: SqlType;
}

/** The only functions the edge function calls (all granted to onepass_mailbox_api). */
export const FUNCTIONS = [
  "ip_gate",
  "credential_key",
  "api_create_mailbox",
  "api_mailbox_info",
  "api_enroll",
  "api_revoke_credential",
  "api_set_push",
  "api_grant_credential",
  "api_set_credential_role",
  "api_set_locator",
  "api_delete_mailbox",
  "api_create_child",
  "locate",
  "api_changes",
  "api_commit",
  "api_record",
  "api_blob_announce",
  "api_blob_lookup",
  "rdv_put",
  "rdv_get",
  "rdv_close",
] as const;

export type Fn = (typeof FUNCTIONS)[number];

export interface Tx {
  call(fn: Fn, args: Arg[]): Promise<Row[]>;
}

export interface Db {
  /**
   * Runs `work` in one transaction (READ COMMITTED). It commits when `work`
   * resolves, in-band refusals included, and rolls back when it throws.
   */
  transaction<T>(work: (tx: Tx) => Promise<T>): Promise<T>;
}

/** Arg helpers. */
export const a = {
  bytea: (value: Uint8Array | null): Arg => ({ value, type: "bytea" }),
  smallint: (value: number | null): Arg => ({ value, type: "smallint" }),
  integer: (value: number | null): Arg => ({ value, type: "integer" }),
  bigint: (value: bigint | null): Arg => ({ value, type: "bigint" }),
  boolean: (value: boolean | null): Arg => ({ value, type: "boolean" }),
  timestamptz: (value: Date | null): Arg => ({ value, type: "timestamptz" }),
  byteaArray: (value: (Uint8Array | null)[]): Arg => ({ value, type: "bytea[]" }),
  smallintArray: (value: (number | null)[]): Arg => ({ value, type: "smallint[]" }),
  integerArray: (value: (number | null)[]): Arg => ({ value, type: "integer[]" }),
  bigintArray: (value: (bigint | null)[]): Arg => ({ value, type: "bigint[]" }),
};

/** The refusal an error from a SQL call stands for. */
export function refusalFromSqlError(e: unknown): Refusal {
  const err = e as { code?: unknown; message?: unknown; detail?: unknown } | null;
  if (
    err && typeof err.code === "string" && /^OP[0-9]{3}$/.test(err.code) && isSqlCode(err.message) &&
    CODES[err.message].status === Number(err.code.slice(2))
  ) {
    let retry: number | null = null;
    if (err.message === "rate_limited" && typeof err.detail === "string" && /^[0-9]{1,9}$/.test(err.detail)) {
      retry = Number(err.detail);
    }
    return new Refusal(err.message, retry);
  }
  // A bug or a transient fault: the SQLSTATE and the server routine go to
  // the function's log, never the message (it can echo input values).
  const e2 = err as { code?: unknown; routine?: unknown } | null;
  console.error(
    "mailbox: SQL call failed",
    e2 && typeof e2.code === "string" ? e2.code : "no SQLSTATE",
    e2 && typeof e2.routine === "string" ? e2.routine : "",
  );
  return new Refusal("retry");
}

function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/**
 * Arrays go over the wire as the text of a Postgres array literal, cast on
 * the server: postgres.js infers an array's type from its first element and
 * mangles NULLs in bytea and bigint arrays.
 */
function arrayLiteral(values: (Uint8Array | number | bigint | null)[]): string {
  return "{" + values.map((v) => {
    if (v === null) return "NULL";
    if (v instanceof Uint8Array) return `"\\\\x${hex(v)}"`;
    if (typeof v === "bigint" || (typeof v === "number" && Number.isSafeInteger(v))) return String(v);
    throw new TypeError("bad array element");
  }).join(",") + "}";
}

function param(arg: Arg): [string, unknown] {
  const v = arg.value;
  if (arg.type.endsWith("[]")) {
    if (!Array.isArray(v)) throw new TypeError("array expected");
    return [`::text::${arg.type}`, arrayLiteral(v)];
  }
  if (typeof v === "bigint") return [`::text::${arg.type}`, v.toString()];
  return [`::${arg.type}`, v];
}

/** SQL text and parameters of one call. Exported for the tests. */
export function callText(fn: Fn, args: Arg[]): { text: string; params: unknown[] } {
  if (!(FUNCTIONS as readonly string[]).includes(fn)) throw new TypeError(`unknown function ${fn}`);
  const casts: string[] = [];
  const params: unknown[] = [];
  args.forEach((arg, i) => {
    const [cast, value] = param(arg);
    casts.push(`$${i + 1}${cast}`);
    params.push(value);
  });
  return { text: `select * from onepass_mailbox.${fn}(${casts.join(", ")})`, params };
}

/** Byte columns come back as Node Buffers: hand plain Uint8Arrays on. */
function plain(row: Row): Row {
  const out: Row = {};
  for (const [k, v] of Object.entries(row)) out[k] = v instanceof Uint8Array ? new Uint8Array(v) : v;
  return out;
}

export interface ConnectOptions {
  /** Pool size of one isolate. */
  max?: number;
}

/** A postgres.js client set up the way the edge function needs it. */
export function client(url: string, opts: ConnectOptions = {}): postgres.Sql<{ bigint: bigint }> {
  return postgres(url, {
    prepare: false,
    max: opts.max ?? 4,
    idle_timeout: 20,
    connect_timeout: 10,
    types: { bigint: postgres.BigInt },
    onnotice: () => {},
    connection: { application_name: "onepass-mailbox-edge" },
  });
}

/** `MAILBOX_DB_URL`: the pooler, in transaction mode, as onepass_mailbox_api. */
export function connect(url: string, opts: ConnectOptions = {}): Db & { end(): Promise<void> } {
  return over(client(url, opts));
}

/** The `Db` of a client (tests share the client to look at its connection). */
export function over(sql: postgres.Sql<{ bigint: bigint }>): Db & { end(): Promise<void> } {
  return {
    transaction<T>(work: (tx: Tx) => Promise<T>): Promise<T> {
      return sql.begin(async (t) => {
        const tx: Tx = {
          async call(fn, args) {
            const { text, params } = callText(fn, args);
            const rows = await t.unsafe(text, params as never[]);
            return Array.from(rows, (r) => plain(r as Row));
          },
        };
        return await work(tx);
      }) as Promise<T>;
    },
    end: () => sql.end({ timeout: 5 }),
  };
}
