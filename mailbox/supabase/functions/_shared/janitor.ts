// The database side of the janitor functions: onepass_mailbox_janitor over
// MAILBOX_JANITOR_DB_URL, plain SQL function calls (the functions set
// onepass.maintenance themselves, and the role's session_user is what
// in_maintenance() checks).
import postgres from "postgres";

export type Row = Record<string, unknown>;

export interface JanitorDb {
  /** `select * from onepass_mailbox.<fn>(<casts>)` in one transaction. */
  call(fn: JanitorFn, params: { value: unknown; cast: string }[]): Promise<Row[]>;
  end(): Promise<void>;
}

/** The only functions the janitor functions call. */
export const JANITOR_FUNCTIONS = ["gc_take", "gc_done", "push_take", "push_forget"] as const;
export type JanitorFn = (typeof JANITOR_FUNCTIONS)[number];

function plain(row: Row): Row {
  const out: Row = {};
  for (const [k, v] of Object.entries(row)) out[k] = v instanceof Uint8Array ? new Uint8Array(v) : v;
  return out;
}

export function connectJanitor(url: string, application: string): JanitorDb {
  const sql = postgres(url, {
    prepare: false,
    max: 1,
    idle_timeout: 20,
    connect_timeout: 10,
    onnotice: () => {},
    connection: { application_name: application },
  });
  return {
    async call(fn, params) {
      if (!(JANITOR_FUNCTIONS as readonly string[]).includes(fn)) throw new TypeError(`unknown function ${fn}`);
      const text = `select * from onepass_mailbox.${fn}(${params.map((p, i) => `$${i + 1}::${p.cast}`).join(", ")})`;
      const rows = await sql.begin((t) => t.unsafe(text, params.map((p) => p.value) as never[]));
      return Array.from(rows, (r) => plain(r as Row));
    },
    end: () => sql.end({ timeout: 5 }),
  };
}

/** SQLSTATE and server routine only: the message can echo input values. */
export function logSqlError(who: string, e: unknown): void {
  const err = e as { code?: unknown; routine?: unknown } | null;
  console.error(
    `${who}: SQL call failed`,
    err && typeof err.code === "string" ? err.code : "no SQLSTATE",
    err && typeof err.routine === "string" ? err.routine : "",
  );
}
