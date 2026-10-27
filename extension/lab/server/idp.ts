// Mock identity providers of the autofill lab (spec 5.2), served under the
// real provider host names with neutral pages: account chooser (the world's
// 2 or 3 accounts of that provider), identifier with the picked account as
// hint, password (Microsoft: identifier then password on two pages; the
// others: both on the identifier page), then a redirect to the site's
// redirect_uri with a one-time code, only when that URI is https on a host of
// the world's sites. The site's /oauth/callback (rp.ts) exchanges the code.
import { randomBytes } from "node:crypto";
import type { ProviderId } from "../gen/model.ts";
import { IDP_PATH, renderIdpPage } from "../gen/render.ts";
import type { IdpContext, IdpPageId } from "../gen/render.ts";
import type { Exchange, LabState } from "./server.ts";

const MSG = { unknown: "Compte introuvable", password: "Mot de passe incorrect", redirect: "Adresse de retour refusée" };

export function handleIdp(provider: ProviderId, x: Exchange, st: LabState): void {
  const accounts = st.world.idp[provider];
  const s = x.session();
  const flow = (s.idp ??= { client: "", redirect: "", hint: "" });
  const page = (id: IdpPageId, ctx: IdpContext = {}) => x.html(renderIdpPage(provider, id, { client: flow.client, ...ctx }));
  const note = (form: string, ok: boolean, fields: string[], reason?: string) =>
    st.ledger.note({ at: Date.now(), host: x.host, kind: "submit", form, ok, fields, ...(reason ? { reason } : {}) });
  const find = (email: string) => accounts.find((a) => a.email.toLowerCase() === email.trim().toLowerCase());

  const finish = (email: string) => {
    let back: URL | undefined;
    try {
      back = new URL(flow.redirect);
    } catch {
      back = undefined;
    }
    if (!back || back.protocol !== "https:" || !st.siteHosts.has(back.hostname)) {
      note("idp_password", false, [], "bad_redirect");
      return page("password", { email, error: MSG.redirect });
    }
    const code = randomBytes(16).toString("base64url");
    st.codes.set(code, { email, provider, host: back.hostname });
    delete flow.pending;
    note("idp_password", true, []);
    back.searchParams.set("code", code);
    return x.redirect(back.toString());
  };

  switch (x.path) {
    case IDP_PATH.chooser:
      if (!x.post) {
        flow.client = x.query.get("client") ?? "";
        flow.redirect = x.query.get("redirect_uri") ?? "";
        return page("chooser", { accounts });
      }
      flow.hint = (x.body.email ?? "").trim();
      return x.redirect(IDP_PATH.identifier);
    case IDP_PATH.identifier: {
      if (!x.post) return page("identifier", { email: flow.hint });
      const email = x.body.email ?? "";
      const acct = find(email);
      if (!acct) {
        note("idp_identifier", false, ["email"], "unknown_user");
        return page("identifier", { email, error: MSG.unknown });
      }
      if (provider === "microsoft") {
        flow.pending = acct.email;
        note("idp_identifier", true, []);
        return x.redirect(IDP_PATH.password);
      }
      if ((x.body.password ?? "") !== acct.password) {
        note("idp_identifier", false, ["password"], "wrong_password");
        return page("identifier", { email: acct.email, error: MSG.password });
      }
      return finish(acct.email);
    }
    case IDP_PATH.password: {
      const acct = flow.pending ? find(flow.pending) : undefined;
      if (!acct) {
        if (x.post) note("idp_password", false, [], "no_pending");
        return x.redirect(IDP_PATH.identifier);
      }
      if (!x.post) return page("password", { email: acct.email });
      if ((x.body.password ?? "") !== acct.password) {
        note("idp_password", false, ["password"], "wrong_password");
        return page("password", { email: acct.email, error: MSG.password });
      }
      return finish(acct.email);
    }
    default:
      return x.notFound();
  }
}
