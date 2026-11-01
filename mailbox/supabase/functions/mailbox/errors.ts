// Error codes of spec 4.6: the snake case name SQL raises and returns in
// band, its HTTP status, and its wire name (the `ErrorCode` variant).

export type Code =
  | "malformed"
  | "bad_signature"
  | "stale_request"
  | "replay"
  | "unknown_credential"
  | "revoked_credential"
  | "frozen"
  | "not_found"
  | "cursor_expired"
  | "too_large"
  | "quota"
  | "rate_limited"
  | "retry"
  | "no_route"
  | "forbidden"
  | "absent";

export const CODES: Record<Code, { status: number; wire: string }> = {
  malformed: { status: 400, wire: "Malformed" },
  bad_signature: { status: 401, wire: "BadSignature" },
  stale_request: { status: 401, wire: "StaleRequest" },
  replay: { status: 401, wire: "Replay" },
  unknown_credential: { status: 403, wire: "UnknownCredential" },
  revoked_credential: { status: 403, wire: "RevokedCredential" },
  frozen: { status: 403, wire: "Frozen" },
  not_found: { status: 404, wire: "NotFound" },
  cursor_expired: { status: 410, wire: "CursorExpired" },
  too_large: { status: 413, wire: "TooLarge" },
  quota: { status: 422, wire: "Quota" },
  rate_limited: { status: 429, wire: "RateLimited" },
  retry: { status: 503, wire: "Retry" },
  // A method and path this function does not serve: told apart from a
  // record that is absent (absent), so a wrong base URL never reads as
  // "no such record" on the client.
  no_route: { status: 404, wire: "NoRoute" },
  // The role of the credential does not allow the request (spec D.7),
  // answered in band by SQL after authentication.
  forbidden: { status: 403, wire: "Forbidden" },
  // The record route only: no record under that key. not_found keeps
  // meaning "mailbox gone" on every route, so a client never reads a
  // deleted mailbox as an absent record.
  absent: { status: 404, wire: "Absent" },
};

export function isCode(s: unknown): s is Code {
  return typeof s === "string" && Object.hasOwn(CODES, s);
}

/** A code an SQL entry point may raise or return: the router's own no_route is not one. */
export function isSqlCode(s: unknown): s is Exclude<Code, "no_route"> {
  return isCode(s) && s !== "no_route";
}

/** A request answered with an `ErrorBody`. */
export class Refusal extends Error {
  constructor(readonly code: Code, readonly retryAfter: number | null = null) {
    super(code);
  }
}
