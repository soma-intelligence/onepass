// Version skew with the app. `unlock` and `vaults` carry an optional `origin` (the page the
// gesture or the save is for). An app from before that field refuses a request with an unknown
// field (`invalid`). The request then goes once more without it, and the field is not sent again
// while this worker lives: the app is an old one. Nothing else is ever retried here.
import type { ResponseFor } from "../bridge/client";
import { type Session, toBgError } from "./session";

export class HostCompat {
  /** The app refused `origin` and took the same request without it. */
  private old = false;

  constructor(private readonly session: Pick<Session, "request">) {}

  /**
   * The bridge `unlock` of a trusted gesture. `origin`: the top-frame origin of the gesture's
   * tab when it is a page (https, or http on a loopback host); none when no page is concerned.
   */
  unlock(origin?: string): Promise<ResponseFor<"unlock">> {
    return this.ask(origin, (o) => this.session.request(o === undefined ? { op: "unlock" } : { op: "unlock", origin: o }));
  }

  /**
   * The vaults a new item may go to. With `origin` (the page the save is for) the vaults of the
   * account that page routes to come first: the first is the default.
   */
  vaults(origin?: string): Promise<ResponseFor<"vaults">> {
    return this.ask(origin, (o) => this.session.request(o === undefined ? { op: "vaults" } : { op: "vaults", origin: o }));
  }

  private async ask<T>(origin: string | undefined, send: (origin?: string) => Promise<T>): Promise<T> {
    if (origin === undefined || this.old) return send();
    try {
      return await send(origin);
    } catch (e) {
      if (toBgError(e).code !== "invalid") throw e;
    }
    const r = await send();
    this.old = true;
    return r;
  }
}
