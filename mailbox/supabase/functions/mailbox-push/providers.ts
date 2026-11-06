// Push providers (spec 4.10). A wake-up carries no content: the provider
// only tells the app to fetch. APNs (plan X1b) is in apns.ts; FCM (plan X4)
// comes with that plan; LogProvider is for tests and for a self-host
// without notifications (clients then poll).

/**
 * `kind` is the wire index of PushKind: 1 Fcm, 2 Apns, 3 UnifiedPush.
 * `send` answers:
 * - "sent": the provider took the message;
 * - "gone": the provider says the token is dead for good (the caller
 *   forgets it);
 * - "retry": a transient fault (the caller may try again, a bounded number
 *   of times).
 * It may also reject, which counts as "retry".
 */
export interface PushProvider {
  kind: number;
  send(token: Uint8Array): Promise<"sent" | "gone" | "retry">;
}

/** Says "sent" and logs the kind and the token length, never the token. */
export class LogProvider implements PushProvider {
  constructor(public kind: number, private log: (message: string) => void = console.log) {}

  send(token: Uint8Array): Promise<"sent" | "gone" | "retry"> {
    this.log(`mailbox-push: wake-up kind ${this.kind} (token of ${token.length} bytes)`);
    return Promise.resolve("sent");
  }
}

/**
 * The providers MAILBOX_PUSH_PROVIDERS names. It has no default: a deployment
 * says what it does with wake-ups, so a hosted instance never runs the log
 * provider by accident.
 * - "none": no provider; queued wake-ups are taken and skipped, clients rely
 *   on Realtime and polling (the hosted instance until plans X1b and X4);
 * - "log": LogProvider for every kind (local stack and tests).
 * Anything else, or nothing, throws: the function fails at boot.
 */
export function providersFromEnv(mode: string | undefined, apns: PushProvider | null = null): PushProvider[] {
  let providers: PushProvider[];
  if (mode === "none") providers = [];
  else if (mode === "log") providers = [1, 2, 3].map((k) => new LogProvider(k));
  else throw new Error("mailbox-push: MAILBOX_PUSH_PROVIDERS must be set to none or log");
  // APNs, when its secrets exist (plan X1b): it takes kind 2 whatever the mode.
  if (apns) providers = [...providers.filter((p) => p.kind !== apns.kind), apns];
  return providers;
}
