// Save prompt (spec 8.5, Save mockup): views `prompt` (new or update),
// `edit` and `saved`, plus the provider-link variant (spec 8.7). The
// password is not part of `save_init`: it is fetched only when the user
// clicks "Afficher", and the page never sends it back (the worker keeps the
// typed or generated one). Exception: "Enregistrer un nouveau login" from the
// menu (`view: "edit"`) opens the edit view with nothing typed on the page;
// the password the user types here is sent with the save.
//
// The prompt is a small, quiet card (founder, 2026-11-03): the site's icon,
// "Enregistrer le login pour <site> ?" and the username, the vault as a
// compact chip, "Pas maintenant" and "Enregistrer"; "Ne jamais proposer",
// the edit view and "Enregistrer comme nouveau login" sit in a small menu.
// A card or an identity typed by hand in a checkout (kinds `card` and
// `identity`) gets the same card: "Enregistrer cette carte ?" with its last
// four digits and expiry (never the number), or "Enregistrer cette adresse ?"
// with the name and city; the vault chip, "Pas maintenant", "Enregistrer".
// No sound, no motion of its own. Left alone AUTO_DISMISS_MS (no pointer or
// focus in it, no menu open), or on "Later", a sign-in card (new or update)
// folds into a small pill in the same corner ("1 login to update", spec 4.2):
// a click opens the card again, the worker drops the pill after PILL_TTL_MS or
// when the tab leaves the site. The cards of a card or an address typed by hand
// still go away by themselves ("later": nothing is kept).
//
// The toast (`view: "toast"`, spec 4.1, 4.4): a login OnePass saved by
// itself. "Login for <site> saved", the username, Undo and Edit (only when
// `undo`: a generated password confirmed at the submission gets neither). Left alone TOAST_MS (same hover and focus rule) it closes. Undo
// asks the worker to delete it (`save_undo`) and says "Removed", or that it
// could not; Edit (`save_edit`) opens a short edit view: name, identifier,
// vault, "Never on this site", Save.
import { ext } from "../shared/browser";
import type { SaveDecision, SaveEdits, SaveOutcome } from "../shared/messages";
import type { SaveInit } from "../shared/ui";
import {
  ClickGuard,
  type FrameDeps,
  autosize,
  call,
  errorText,
  h,
  icon,
  mark,
  messageBlock,
  mount,
  observeSize,
  observeVisibility,
  providerLabel,
  realTimers,
  siteTile,
  tile,
  vaultColor,
  tokenFromHash,
  wayArt,
} from "./components";
import { t } from "../shared/i18n";
import { parseEmpty, parseOutcome, parsePassword, parseSaveInit } from "./parse";

/** Asked for by the edit view: the content script clamps it to the frame's largest height. */
const FULL_HEIGHT = 2000;

/** The saved confirmation closes itself after this delay. */
export const SAVED_CLOSE_MS = 2500;

/** Left alone this long, the card goes away and the sign-in waits in the popup. */
export const AUTO_DISMISS_MS = 20_000;

/** The toast of a login saved by itself stays this long when nobody looks at it. */
export const TOAST_MS = 8000;

const MASK = "••••••••••••";

export const RULES: readonly { value: SaveEdits["rule"]; label: string }[] = [
  { value: "domain", label: t("save.wholeDomain") },
  { value: "exact_host", label: t("save.exactSubdomain") },
  { value: "exact_url", label: t("save.exactUrl") },
  { value: "never", label: t("save.neverFill") },
];

export interface SaveHandle {
  ready: Promise<void>;
}

interface Draft {
  title: string;
  username: string;
  vaultId: string;
  rule: SaveEdits["rule"];
  tags: string[];
  /** Shown in clear (revealed or generated), else null. */
  password: string | null;
  revealed: boolean;
  /** New login from the menu: the password typed here ("" when generated). */
  typed: string;
}

export function mountSave(root: HTMLElement, deps: FrameDeps): SaveHandle {
  const now = deps.now ?? (() => performance.now());
  const timers = deps.timers ?? realTimers;
  const guard = new ClickGuard({ now, ...(deps.trusted ? { trusted: deps.trusted } : {}) });
  const token = tokenFromHash(deps.hash);
  const container = h("div", { class: "save fit" });
  mount(root, container);
  (deps.observe ?? observeVisibility)(container, (v) => guard.setVisibility(v));
  // The prompt is as tall as its content; the edit view takes the whole frame.
  let fit = true;
  /** The folded pill's box: the frame then shrinks to its width too, so nothing around it blocks the page. */
  let pillBox: HTMLElement | null = null;
  let sentWidth = 0;
  const sendSize = (height: number) => {
    if (!token) return;
    const m: { type: "save_resize"; token: string; height: number; width?: number } = { type: "save_resize", token, height: fit ? height : FULL_HEIGHT };
    const w = pillBox ? Math.ceil(pillBox.offsetWidth) : 0;
    if (w > 0) m.width = w;
    sentWidth = w;
    void call(deps.send, m, parseEmpty);
  };
  const remeasure = autosize(container, sendSize, deps.observeSize);
  /** After a fold or an unfold: the size goes out even when the height did not change. */
  const resendSize = () => {
    const height = Math.ceil(container.scrollHeight);
    if (height > 0) sendSize(height);
  };

  let init: SaveInit | null = null;
  let draft: Draft | null = null;
  let mode: "new" | "update" = "new";
  let more = false;
  let picking = false;

  // ---- auto-dismiss: only while nobody is looking at or using the card ----
  let hovered = false;
  let focused = false;
  let quietTimer: unknown = null;
  let quietOn = false;
  /** How long the card or toast waits, and what it does then. */
  let quietMs = AUTO_DISMISS_MS;
  let quietDone = () => {
    if (token) void call(deps.send, { type: "save_decide", token, decision: "later" }, parseEmpty);
  };
  const stopQuiet = () => {
    if (quietTimer !== null) timers.clearTimeout(quietTimer);
    quietTimer = null;
  };
  const armQuiet = () => {
    stopQuiet();
    if (!quietOn || hovered || focused || more || picking) return;
    quietTimer = timers.setTimeout(() => {
      quietTimer = null;
      if (!quietOn || hovered || focused || more || picking) return;
      quietOn = false;
      quietDone();
    }, quietMs);
  };
  container.addEventListener("pointerenter", () => {
    hovered = true;
    stopQuiet();
  });
  container.addEventListener("pointerleave", () => {
    hovered = false;
    armQuiet();
  });
  container.addEventListener("focusin", () => {
    focused = true;
    stopQuiet();
  });
  container.addEventListener("focusout", (e) => {
    if (e.relatedTarget instanceof Node && container.contains(e.relatedTarget)) return;
    focused = false;
    armQuiet();
  });

  const btn = (label: string, cls: string, fn: () => void, attrs: Record<string, string> = {}) =>
    h("button", { class: cls, attrs: { type: "button", ...attrs }, on: { click: guard.wrap(fn) } }, label);

  const iconBtn = (label: string, glyph: Parameters<typeof icon>[0], fn: () => void) =>
    h("button", { class: "btn-icon", attrs: { type: "button", "aria-label": label }, on: { click: guard.wrap(fn) } }, icon(glyph, 12));

  const show = (...children: (HTMLElement | null)[]) => {
    mount(container, ...children);
    guard.reset();
    remeasure();
  };
  const setFit = (on: boolean) => {
    fit = on;
    container.classList.toggle("fit", on);
  };

  const errLine = () => h("p", { class: "error-line", attrs: { role: "alert" } });

  const closeSoon = () => {
    timers.setTimeout(() => {
      if (token) void call(deps.send, { type: "save_close", token }, parseEmpty);
    }, SAVED_CLOSE_MS);
  };

  const decide = async (decision: SaveDecision, err: HTMLElement, saved: (o: SaveOutcome) => void) => {
    if (!token || !init || !draft) return;
    const msg: { type: "save_decide"; token: string; decision: SaveDecision; edits?: SaveEdits } = {
      type: "save_decide",
      token,
      decision,
    };
    if (decision === "save" && (init.kind === "card" || init.kind === "identity")) {
      // Only the vault: the worker holds what was typed in the page.
      msg.edits = { title: "", username: "", password: "", vaultId: draft.vaultId, rule: "domain", tags: [] };
    } else if (decision === "save" && init.kind === "login") {
      msg.edits = {
        title: draft.title,
        username: draft.username,
        // Never sent back: the worker holds the typed or generated password,
        // except one typed in this very page (new login from the menu).
        password: init.view === "edit" ? draft.typed : "",
        vaultId: draft.vaultId,
        rule: draft.rule,
        tags: draft.tags,
      };
    }
    const r = await call(deps.send, msg, parseOutcome);
    if (!r.ok) {
      err.textContent = errorText(r.code);
      return;
    }
    if (decision !== "dismiss") saved(r.value);
  };

  const vaultName = () => init?.vaults.find((v) => v.id === draft?.vaultId)?.name ?? "";

  const vaultSelect = () => {
    const sel = h("select", { class: "select", attrs: { "aria-label": t("term.vault") } });
    for (const v of init?.vaults ?? []) {
      const o = h("option", { attrs: { value: v.id } }, v.name);
      if (v.id === draft?.vaultId) o.selected = true;
      sel.append(o);
    }
    sel.addEventListener("change", () => {
      if (draft) draft.vaultId = sel.value;
    });
    return sel;
  };

  /** "Enregistrer" of the current view; disabled while nothing can be saved. */
  let saveBtn: HTMLButtonElement | null = null;
  /** New login from the menu: no password typed or generated yet. */
  const noPassword = (d: Draft) => init?.view === "edit" && d.typed === "" && d.password === null;
  const updateSave = (d: Draft) => {
    if (saveBtn) saveBtn.disabled = (init?.vaults.length ?? 0) === 0 || noPassword(d);
  };

  /** Vault choice and "Enregistrer"; with no vault, nothing can be saved. */
  const saveActions = (cls: string, err: HTMLElement, d: Draft) => {
    const save = btn(t("common.save"), "btn btn-primary", () =>
      void decide("save", err, (o) =>
        o.outcome === "already" ? renderOutcome(o, d) : renderSaved(t("save.titleSaved", { title: d.title }), t("save.inValue", { value: o.vault ?? vaultName() })),
      ),
    );
    saveBtn = save;
    updateSave(d);
    if ((init?.vaults.length ?? 0) > 0) return h("div", { class: cls }, vaultSelect(), save);
    save.disabled = true;
    return h("div", { class: cls }, h("span", { class: "stack note no-vault" }, t("save.noVaultAvailable")), save);
  };

  const header = (title: string, withMore: boolean) =>
    h(
      "div",
      { class: "save-head" },
      mark("m"),
      h("h1", null, title),
      withMore
        ? iconBtn(t("save.options"), "more", () => {
            more = !more;
            renderPrompt();
          })
        : null,
      iconBtn(t("common.close"), "close", () => void decide("dismiss", errLine(), () => undefined)),
    );

  function renderSaved(title: string, sub: string): void {
    setFit(true);
    quietOn = false;
    stopQuiet();
    show(
      h(
        "div",
        { class: "saved quiet", attrs: { role: "status" } },
        h("span", { class: "ok-dot", attrs: { "aria-hidden": "true" } }, icon("check", 11)),
        h("span", { class: "stack" }, h("span", { class: "t1" }, title), sub !== "" ? h("span", { class: "t2" }, sub) : null),
        btn(t("common.close"), "btn-link", () => {
          if (token) void call(deps.send, { type: "save_close", token }, parseEmpty);
        }),
      ),
    );
    closeSoon();
  }

  /** What a save from the card did, in one line. */
  function renderOutcome(o: SaveOutcome, d: Draft): void {
    if (o.outcome === "already") renderSaved(t("save.alreadyInOnepass"), d.username);
    else if (o.outcome === "updated") renderSaved(t("save.passwordUpdated"), d.username);
    else renderSaved(o.vault !== undefined ? t("save.savedIn", { vault: o.vault }) : t("save.loginSaved"), d.username);
  }

  const never = () => {
    if (!init) return;
    const err = errLine();
    void decide("never", err, () => renderSaved(t("save.onepassWontOfferAnything"), t("save.changeItInSettings")));
  };

  /**
   * Spec 8.7, after a sign-in through a provider by hand: one compact
   * prompt (not a sheet) that names the site, the provider and the very
   * provider account (its item) the link will point to.
   */
  function renderProviderLink(i: SaveInit): void {
    setFit(true);
    const p = i.provider;
    const err = errLine();
    const name = p ? providerLabel(p.id) : "";
    const art = wayArt({ kind: "login", has_password: false, methods: [], icon_letter: i.title.charAt(0).toUpperCase() || "O" }, p?.id, "m");
    show(
      h(
        "div",
        { class: "save-body link", attrs: { role: "dialog", "aria-label": t("save.saveLink") } },
        header(t("save.rememberLink"), true),
        more ? moreMenu(i) : null,
        h(
          "div",
          { class: "link-card" },
          art,
          h(
            "span",
            { class: "stack" },
            h("span", { class: "t1 link-line" }, p ? `${i.site} ↔ ${name}` : i.site),
            p ? h("span", { class: "line2" }, h("span", { class: "t2" }, p.email), p.title ? h("span", { class: "meta" }, ` · ${p.title}`) : null) : null,
          ),
        ),
        h(
          "p",
          { class: "note" },
          p
            ? t("save.nextTimeOnepassSigns", { name })
            : t("save.nextTimeOnepassSigns2"),
        ),
        h(
          "div",
          { class: "actions" },
          h("span", { class: "stack" }),
          btn(t("save.notNow"), "btn", () => void decide("dismiss", err, () => undefined)),
          btn(t("common.save"), "btn btn-primary", () =>
            void decide("save", err, () =>
              renderSaved(t("save.linkSaved"), p ? `${i.site} ↔ ${name} (${p.email})` : i.site),
            ),
          ),
        ),
        err,
      ),
    );
  }

  const moreMenu = (i: SaveInit) =>
    h(
      "div",
      { class: "more", attrs: { role: "menu" } },
      btn(t("save.neverForSite"), "", never, { role: "menuitem" }),
      i.kind === "login" && mode === "new" ? btn(t("save.editBeforeSaving"), "", () => renderEdit(), { role: "menuitem" }) : null,
      i.kind === "login" && mode === "update"
        ? btn(t("save.saveAsNew"), "", () => {
            mode = "new";
            more = false;
            renderPrompt();
          }, { role: "menuitem" })
        : null,
      i.kind === "provider_link" ? btn(t("save.notNow"), "", () => void decide("dismiss", errLine(), () => undefined), { role: "menuitem" }) : null,
    );

  /** The vault Save uses: a compact chip, the list under it when opened. */
  const vaultLabel = (v: SaveInit["vaults"][number]) => {
    const accounts = new Set((init?.vaults ?? []).map((x) => x.account ?? ""));
    return accounts.size > 1 && v.account ? `${v.account} · ${v.name}` : v.name;
  };

  /** The title with the site name kept on one line (no break at its hyphens). */
  const titleParts = (title: string, site: string): (string | HTMLElement)[] => {
    const at = title.indexOf(site);
    if (at === -1 || site === "") return [title];
    return [title.slice(0, at), h("span", { class: "sc-site" }, site), title.slice(at + site.length)];
  };

  const chip = (d: Draft): HTMLElement | null => {
    if (init?.locked) return h("span", { class: "sc-chip sc-chip-locked" }, icon("lock", 11), h("span", { class: "sc-chip-name" }, t("save.lockedChip")));
    const vaults = init?.vaults ?? [];
    const v = vaults.find((x) => x.id === d.vaultId);
    if (!v) return null;
    const dot = h("span", { class: "vault-dot", attrs: { "aria-hidden": "true" } });
    const el =
      vaults.length > 1
        ? h(
            "button",
            {
              class: "sc-chip",
              attrs: { type: "button", "aria-haspopup": "listbox", "aria-expanded": String(picking), "aria-label": t("save.vaultChip", { name: vaultLabel(v) }) },
              on: {
                click: guard.wrap(() => {
                  picking = !picking;
                  renderPrompt();
                }),
              },
            },
            dot,
            h("span", { class: "sc-chip-name" }, v.name),
            icon("chevron", 10),
          )
        : h("span", { class: "sc-chip", attrs: { "aria-label": t("save.vaultChip", { name: vaultLabel(v) }) } }, dot, h("span", { class: "sc-chip-name" }, v.name));
    // Several accounts: the chip shows the vault, its label and tooltip name the account too.
    el.title = vaultLabel(v);
    el.style.setProperty("--vault", vaultColor(v.id));
    return el;
  };

  const picker = (d: Draft) =>
    h(
      "div",
      { class: "sc-vaults", attrs: { role: "listbox", "aria-label": t("save.chooseVault") } },
      ...(init?.vaults ?? []).map((v) => {
        const o = h(
          "button",
          {
            class: "sc-vault",
            attrs: { type: "button", role: "option", "aria-selected": String(v.id === d.vaultId) },
            on: {
              click: guard.wrap(() => {
                d.vaultId = v.id;
                picking = false;
                renderPrompt();
              }),
            },
          },
          h("span", { class: "vault-dot", attrs: { "aria-hidden": "true" } }),
          h("span", { class: "sc-vault-name" }, vaultLabel(v)),
          v.id === d.vaultId ? icon("check", 11) : null,
        );
        o.style.setProperty("--vault", vaultColor(v.id));
        return o;
      }),
    );

  /** A card or identity typed in the page: what it is, the vault, "Pas maintenant", "Enregistrer". */
  function renderForm(i: SaveInit, d: Draft): void {
    setFit(true);
    // A card or an address: it is put away by itself ("later", nothing is kept), never folded.
    quietMs = AUTO_DISMISS_MS;
    quietDone = () => {
      if (token) void call(deps.send, { type: "save_decide", token, decision: "later" }, parseEmpty);
    };
    const err = errLine();
    const isCard = i.kind === "card";
    const updating = isCard && i.status === "update" && i.update !== undefined;
    const title = isCard
      ? t(updating ? "save.updateCard" : "save.saveCard")
      : t(i.identity?.place !== undefined ? "save.saveAddress" : "save.saveIdentity");
    const c = i.card;
    const line1 = isCard
      ? [c ? t("save.cardEnding", { last4: c.last4 }) : "", c?.exp !== undefined ? t("save.cardExpires", { exp: c.exp }) : ""].filter((x) => x !== "").join(" · ")
      : [i.identity?.name, i.identity?.email].filter((x): x is string => x !== undefined && x !== "").join(" · ");
    const line2 = isCard ? (c?.holder ?? "") : (i.identity?.place ?? "");
    const done = (o: SaveOutcome) =>
      o.outcome === "already" ? renderSaved(t("save.alreadyInOnepass"), line1) : renderSaved(
        updating ? t("save.cardUpdated") : isCard ? t("save.cardSaved") : t("save.identitySaved"),
        o.outcome === "updated" || updating ? line1 : o.vault !== undefined ? t("save.inValue", { value: o.vault }) : line1,
      );
    const primary = updating
      ? btn(t("save.update"), "btn-text sc-primary", () => void decide("update", err, done))
      : btn(t("common.save"), "btn-text sc-primary", () => void decide("save", err, done));
    if (!updating && i.vaults.length === 0) primary.disabled = true;
    show(
      h(
        "div",
        { class: "save-card", attrs: { role: "dialog", "aria-label": title } },
        h(
          "div",
          { class: "sc-row" },
          siteTile(i.origin, i.title, 28),
          h(
            "span",
            { class: "stack" },
            h("span", { class: "sc-title" }, title),
            line1 !== "" ? h("span", { class: "sc-sub" }, line1) : null,
            line2 !== "" ? h("span", { class: "sc-sub" }, line2) : null,
          ),
          h(
            "button",
            {
              class: "btn-icon sc-more",
              attrs: { type: "button", "aria-label": t("save.options"), "aria-haspopup": "menu", "aria-expanded": String(more) },
              on: {
                click: guard.wrap(() => {
                  more = !more;
                  picking = false;
                  renderPrompt();
                }),
              },
            },
            icon("more", 12),
          ),
        ),
        more ? h("div", { class: "more", attrs: { role: "menu" } }, btn(t("save.neverForSite"), "", never, { role: "menuitem" })) : null,
        picking && !updating ? picker(d) : null,
        h(
          "div",
          { class: "sc-foot" },
          updating ? h("span", { class: "sc-note" }, "") : chip(d) ?? h("span", { class: "sc-note" }, ""),
          h("span", { class: "sc-gap" }),
          btn(t("save.notNow"), "btn-text sc-quiet", () => void decide("dismiss", err, () => undefined)),
          primary,
        ),
        err,
      ),
    );
    armQuiet();
  }

  function renderPrompt(): void {
    if (!init || !draft) return;
    const i = init;
    if (i.kind === "provider_link") {
      renderProviderLink(i);
      return;
    }
    if (i.kind === "card" || i.kind === "identity") {
      renderForm(i, draft);
      return;
    }
    setFit(true);
    const d = draft;
    const err = errLine();
    const updating = mode === "update" && i.update !== undefined;
    const title = updating ? t("save.updatePasswordFor", { site: i.site }) : t("save.saveLoginFor", { site: i.site });
    const sub = updating && i.update && i.update.title !== "" ? `${i.update.title} · ${d.username}` : d.username;
    const primary = updating
      ? btn(t("save.updateAction"), "btn-text sc-primary", () => void decide("update", err, (o) => renderOutcome(o.outcome === "done" ? { outcome: "updated" } : o, d)))
      : btn(t("common.save"), "btn-text sc-primary", () =>
          void decide("save", err, (o) => renderOutcome(o.outcome === "done" ? { outcome: "saved", vault: vaultName() } : o, d)),
        );
    if (!updating && !i.locked && i.vaults.length === 0) primary.disabled = true;
    show(
      h(
        "div",
        { class: "save-card", attrs: { role: "dialog", "aria-label": title } },
        h(
          "div",
          { class: "sc-row" },
          siteTile(i.origin, i.title, 28),
          h("span", { class: "stack" }, h("span", { class: "sc-title" }, ...titleParts(title, i.site)), sub !== "" ? h("span", { class: "sc-sub" }, sub) : null),
          h(
            "button",
            {
              class: "btn-icon sc-more",
              attrs: { type: "button", "aria-label": t("save.options"), "aria-haspopup": "menu", "aria-expanded": String(more) },
              on: {
                click: guard.wrap(() => {
                  more = !more;
                  picking = false;
                  renderPrompt();
                }),
              },
            },
            icon("more", 12),
          ),
        ),
        more ? moreMenu(i) : null,
        picking && !updating ? picker(d) : null,
        h(
          "div",
          { class: "sc-foot" },
          updating ? h("span", { class: "sc-note" }, "") : chip(d) ?? h("span", { class: "sc-note" }, ""),
          h("span", { class: "sc-gap" }),
          btn(t("save.later"), "btn-text sc-quiet", () => void fold()),
          primary,
        ),
        err,
      ),
    );
    // Left alone, or on "Later", the card folds into its pill (spec 4.2).
    quietMs = AUTO_DISMISS_MS;
    quietDone = () => void fold();
    armQuiet();
  }

  /** The card folds into a small pill in the same corner; the worker keeps the sign-in PILL_TTL_MS. */
  async function fold(): Promise<void> {
    if (!token || !init) return;
    quietOn = false;
    stopQuiet();
    more = false;
    picking = false;
    const r = await call(deps.send, { type: "save_fold", token }, parseEmpty);
    if (!r.ok) {
      // The sign-in is gone from the worker (expired): nothing to come back to.
      void call(deps.send, { type: "save_close", token }, parseEmpty);
      return;
    }
    renderPill();
  }

  /** A click on the pill: the card again, quiet for AUTO_DISMISS_MS once more. */
  async function unfold(): Promise<void> {
    if (!token) return;
    const r = await call(deps.send, { type: "save_unfold", token }, parseEmpty);
    if (!r.ok) {
      void call(deps.send, { type: "save_close", token }, parseEmpty);
      return;
    }
    quietOn = true;
    pillBox = null;
    renderPrompt();
    resendSize();
  }

  /** "1 login to update" / "1 login to save": one tap target, a small x to put it away for good. */
  function renderPill(): void {
    if (!init) return;
    const i = init;
    setFit(true);
    const updating = mode === "update" && i.update !== undefined;
    const label = t(updating ? "save.updatePill" : "save.savePill");
    const wrap = h(
        "div",
        { class: "save-pill-wrap" },
        h(
          "div",
          { class: "save-pill", attrs: { role: "group", "aria-label": label } },
          h(
            "button",
            { class: "save-pill-main", attrs: { type: "button" }, on: { click: guard.wrap(() => void unfold()) } },
            siteTile(i.origin, i.title, 20),
            h("span", { class: "save-pill-text" }, label),
          ),
          iconBtn(t("common.close"), "close", () => void decide("dismiss", errLine(), () => undefined)),
        ),
    );
    pillBox = wrap;
    show(wrap);
    resendSize();
    // The pill's own width moves without its height (a late font): the frame follows.
    (deps.observeSize ?? observeSize)(wrap, () => {
      if (pillBox === wrap && Math.ceil(wrap.offsetWidth) !== sentWidth) resendSize();
    });
  }

  function renderEdit(): void {
    if (!init || !draft || !token) return;
    setFit(false);
    // Editing: the card never leaves by itself.
    quietOn = false;
    stopQuiet();
    const i = init;
    const d = draft;
    const tok = token;
    const err = errLine();
    const title = h("input", { class: "title-input", attrs: { type: "text", "aria-label": t("save.title"), maxlength: "256" } });
    title.value = d.title;
    title.addEventListener("input", () => (d.title = title.value));
    const user = h("input", { attrs: { type: "text", "aria-label": t("save.username"), maxlength: "1024" } });
    user.value = d.username;
    user.addEventListener("input", () => (d.username = user.value));
    const fresh = i.view === "edit";
    let pwd: HTMLElement;
    if (fresh) {
      const input = h("input", {
        class: "field-value mono pwd-value",
        attrs: { type: d.password !== null ? "text" : "password", "aria-label": t("menu.password"), maxlength: "4096", autocomplete: "off" },
      });
      input.value = d.password ?? d.typed;
      input.addEventListener("input", () => {
        d.typed = input.value;
        // Cleared after a generation: the generated one is no longer shown, nor saved.
        if (input.value === "") d.password = null;
        updateSave(d);
      });
      pwd = input;
    } else {
      pwd = h("span", { class: "field-value mono pwd-value" }, d.revealed && d.password !== null ? d.password : MASK);
    }
    const reveal = btn(d.revealed ? t("common.hide") : t("common.show"), "btn-link", async () => {
      if (d.revealed) {
        d.revealed = false;
        renderEdit();
        return;
      }
      if (d.password === null) {
        const r = await call(deps.send, { type: "save_reveal", token: tok }, parsePassword);
        if (!r.ok) {
          err.textContent = errorText(r.code);
          return;
        }
        d.password = r.value.password;
      }
      d.revealed = true;
      renderEdit();
    });
    const generate = btn(t("common.generate"), "btn-link", async () => {
      const r = await call(deps.send, { type: "save_generate", token: tok }, parsePassword);
      if (!r.ok) {
        err.textContent = errorText(r.code);
        return;
      }
      d.password = r.value.password;
      // The worker now holds this one; a later edit of the field replaces it.
      d.typed = "";
      d.revealed = true;
      renderEdit();
    });
    const rule = h("select", { class: "select", attrs: { "aria-label": t("save.match") } });
    for (const x of RULES) {
      const o = h("option", { attrs: { value: x.value } }, x.label);
      if (x.value === d.rule) o.selected = true;
      rule.append(o);
    }
    rule.addEventListener("change", () => (d.rule = rule.value as SaveEdits["rule"]));
    const tags = h("div", { class: "tags" });
    for (const tag of d.tags) {
      tags.append(
        btn(tag, "tag", () => {
          d.tags = d.tags.filter((x) => x !== tag);
          renderEdit();
        }, { "aria-label": t("save.removeTagTag", { tag }) }),
      );
    }
    const tagInput = h("input", { class: "tag-input", attrs: { type: "text", "aria-label": t("save.addTag"), placeholder: t("save.addTag"), maxlength: "64" } });
    tagInput.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      e.preventDefault();
      const v = tagInput.value.trim();
      if (v !== "" && !d.tags.includes(v) && d.tags.length < 32) d.tags.push(v);
      renderEdit();
      container.querySelector<HTMLInputElement>(".tag-input")?.focus();
    });
    tags.append(tagInput);
    show(
      h(
        "div",
        { class: "save-body edit-head", attrs: { role: "dialog", "aria-label": t("save.saveItem") } },
        h(
          "div",
          { class: "save-head" },
          mark("m"),
          h("h1", null, t("save.saveItem")),
          iconBtn(t("common.close"), "close", () => (fresh ? void decide("dismiss", errLine(), () => undefined) : renderPrompt())),
        ),
      ),
      h(
        "div",
        { class: "edit-sheet" },
        title,
        h(
          "div",
          { class: "group" },
          h("label", { class: "cell" }, h("span", { class: "stack" }, h("span", { class: "cell-label" }, t("save.username")), user)),
          h(
            "div",
            { class: "cell" },
            h("span", { class: "stack" }, h("span", { class: "cell-label" }, t("menu.password")), pwd),
            fresh ? null : reveal,
            generate,
          ),
        ),
        h(
          "div",
          { class: "group" },
          h(
            "div",
            { class: "cell" },
            h("span", { class: "stack" }, h("span", { class: "cell-label" }, t("popup.website")), h("span", { class: "field-value" }, i.origin)),
            rule,
          ),
        ),
        h("div", { class: "stack" }, h("span", { class: "cell-label" }, t("save.tags")), tags),
        err,
      ),
      saveActions("actions save-foot", err, d),
    );
  }

  /** A login OnePass saved by itself: what it is, Undo (when offered) and Edit. */
  function renderToast(i: SaveInit, d: Draft): void {
    setFit(true);
    const err = errLine();
    const tok = token;
    const undo = i.undo
      ? btn(t("save.undo"), "btn-link", async () => {
          if (!tok) return;
          const r = await call(deps.send, { type: "save_undo", token: tok }, parseEmpty);
          if (!r.ok) {
            // Too late, edited since, or gone: the login stays, the toast says so.
            err.textContent = t("save.undoFailed");
            return;
          }
          renderSaved(t("save.removed"), "");
        })
      : null;
    const edit = i.undo
      ? btn(t("save.edit"), "btn-link", async () => {
          if (!tok) return;
          const r = await call(deps.send, { type: "save_edit", token: tok }, parseEmpty);
          if (!r.ok) {
            err.textContent = errorText(r.code);
            return;
          }
          renderToastEdit(d);
        })
      : null;
    show(
      h(
        "div",
        { class: "saved quiet toast", attrs: { role: "status" } },
        h("span", { class: "ok-dot", attrs: { "aria-hidden": "true" } }, icon("check", 11)),
        h("span", { class: "stack" }, h("span", { class: "t1" }, t("save.toastSaved", { site: i.site })), d.username !== "" ? h("span", { class: "t2" }, d.username) : null),
        undo,
        edit,
      ),
      err,
    );
    quietMs = TOAST_MS;
    quietDone = () => {
      if (tok) void call(deps.send, { type: "save_close", token: tok }, parseEmpty);
    };
    quietOn = true;
    armQuiet();
  }

  /** The toast's Edit: name, identifier, vault, "Never on this site"; Save amends the saved login. */
  function renderToastEdit(d: Draft): void {
    if (!token) return;
    const tok = token;
    setFit(false);
    quietOn = false;
    stopQuiet();
    const err = errLine();
    const title = h("input", { class: "title-input", attrs: { type: "text", "aria-label": t("save.title"), maxlength: "256" } });
    title.value = d.title;
    title.addEventListener("input", () => (d.title = title.value));
    const user = h("input", { attrs: { type: "text", "aria-label": t("save.username"), maxlength: "1024" } });
    user.value = d.username;
    user.addEventListener("input", () => (d.username = user.value));
    show(
      h(
        "div",
        { class: "save-body edit-head", attrs: { role: "dialog", "aria-label": t("save.edit") } },
        h(
          "div",
          { class: "save-head" },
          mark("m"),
          h("h1", null, t("save.edit")),
          iconBtn(t("common.close"), "close", () => void call(deps.send, { type: "save_close", token: tok }, parseEmpty)),
        ),
      ),
      h(
        "div",
        { class: "edit-sheet" },
        title,
        h("div", { class: "group" }, h("label", { class: "cell" }, h("span", { class: "stack" }, h("span", { class: "cell-label" }, t("save.username")), user))),
        btn(t("save.neverForSite"), "btn-link", never),
        err,
      ),
      saveActions("actions save-foot", err, d),
    );
  }

  async function load(): Promise<void> {
    if (!token) {
      show(messageBlock(errorText("invalid")));
      return;
    }
    const r = await call(deps.send, { type: "save_init", token }, parseSaveInit);
    if (!r.ok) {
      show(messageBlock(r.code === "unpaired" ? t("menu.pairOnepassFromToolbar") : errorText(r.code)));
      return;
    }
    init = r.value;
    mode = init.status === "update" && init.update ? "update" : "new";
    draft = {
      title: init.title,
      username: init.username,
      vaultId: init.defaultVault !== undefined && init.vaults.some((v) => v.id === init?.defaultVault) ? init.defaultVault : (init.vaults[0]?.id ?? ""),
      rule: "domain",
      tags: [],
      password: null,
      revealed: false,
      typed: "",
    };
    if (init.view === "edit") renderEdit();
    else if (init.view === "saved") renderSaved(t("save.titleSaved", { title: init.title }), init.username);
    else if (init.view === "toast") renderToast(init, draft);
    else if (init.folded && init.kind === "login") renderPill();
    else {
      quietOn = init.kind !== "provider_link";
      renderPrompt();
    }
  }

  return { ready: load() };
}

if (typeof document !== "undefined" && ext?.runtime?.id) {
  const root = document.getElementById("root");
  if (root) mountSave(root, { send: (m) => ext.runtime.sendMessage(m), hash: location.hash });
}
