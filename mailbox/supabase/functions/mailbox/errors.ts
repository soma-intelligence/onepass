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
  | "retry";

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
};

export function isCode(s: unknown): s is Code {
  return typeof s === "string" && Object.hasOwn(CODES, s);
}

/** A request answered with an `ErrorBody`. */
export class Refusal extends Error {
  constructor(readonly code: Code, readonly retryAfter: number | null = null) {
    super(code);
  }
}
