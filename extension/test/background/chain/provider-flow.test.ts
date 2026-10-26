// Manual provider sign-in tracking and the link proposal (spec 8.7).
import { describe, expect, it } from "vitest";
import { PROVIDER_FLOW_TTL_MS, ProviderFlows } from "../../../src/background/chain/provider-flow";
import type { CsContext } from "../../../src/background/frames";
import type { SavePending } from "../../../src/background/save";
import type { PageAnalysis } from "../../../src/shared/messages";
import { FakeArea } from "../fake-ext";

const SITE = "https://atlas-cloud.test";
const GOOGLE = "https://accounts.google.com";

const empty = (forms: PageAnalysis["forms"] = []): PageAnalysis => ({
  url: `${SITE}/app`,
  forms,
  captcha: false,
  push: false,
  providerButtons: [],
  accountChooser: [],
});

const acct = (id: string, email: string) => ({ item_id: id, subtitle: email });

function setup(linked?: string, accounts = [acct("g_perso", "alex.perso@example.com"), acct("g_pro", "alex.pro@example.com")]) {
  const clock = { t: 1_000 };
  const area = new FakeArea();
  const requests: Record<string, unknown>[] = [];
  const opened: SavePending[] = [];
  const flows = new ProviderFlows({
    area,
    session: {
      request: (async (r: Record<string, unknown>) => {
        requests.push(r);
        return linked === undefined ? { accounts } : { accounts, linked_item_id: linked };
      }) as never,
    },
    saves: { open: async (p: SavePending) => (opened.push(structuredClone(p)), "tok") },
    neverSave: { has: async () => false },
    now: () => clock.t,
  });
  const cs = (origin: string, frameId = 0, documentId: string | null = "doc-9"): CsContext =>
    documentId === null ? { tabId: 7, frameId, origin } : { tabId: 7, frameId, origin, documentId };
  return { flows, clock, area, requests, opened, cs };
}

async function goRoundTrip(t: ReturnType<typeof setup>, pick = "alex.pro@example.com") {
  await t.flows.onProviderClick(t.cs(SITE), "google");
  await t.flows.onNavigation(7, `${GOOGLE}/o/oauth2/auth`);
  await t.flows.onAccountClick(t.cs(GOOGLE), pick);
  await t.flows.onNavigation(7, `${SITE}/callback`);
}

describe("provider flow", () => {
  it("proposes the link with the chosen account when back on the site without a form", async () => {
    const t = setup();
    await goRoundTrip(t);
    await t.flows.onAnalysis(empty(), t.cs(SITE));
    expect(t.requests).toEqual([{ op: "provider_accounts", ctx: "save_prompt", provider: "google", origin: SITE }]);
    expect(t.opened).toEqual([
      {
        tabId: 7,
        origin: SITE,
        documentId: "doc-9",
        kind: "provider_link",
        status: "new",
        username: "alex.pro@example.com",
        password: "",
        provider: { id: "google", accountItemId: "g_pro", email: "alex.pro@example.com" },
        topOrigin: SITE,
      },
    ]);
    // Once.
    await t.flows.onAnalysis(empty(), t.cs(SITE));
    expect(t.opened).toHaveLength(1);
  });

  it("without a documentId (Firefox) the prompt is pinned to the top origin", async () => {
    const t = setup();
    await goRoundTrip(t);
    await t.flows.onAnalysis(empty(), t.cs(SITE, 0, null));
    expect(t.opened).toHaveLength(1);
    expect(t.opened[0]?.documentId).toBeUndefined();
    expect(t.opened[0]?.topOrigin).toBe(SITE);
  });

  it("tracking survives a worker restart (storage.session)", async () => {
    const t = setup();
    await goRoundTrip(t);
    const again = new ProviderFlows({
      area: t.area,
      session: { request: (async () => ({ accounts: [acct("g_pro", "alex.pro@example.com")] })) as never },
      saves: { open: async (p: SavePending) => (t.opened.push(p), "tok") },
      neverSave: { has: async () => false },
      now: () => t.clock.t,
    });
    await again.onAnalysis(empty(), t.cs(SITE));
    expect(t.opened[0]?.provider?.accountItemId).toBe("g_pro");
  });

  it("nothing when a link already exists", async () => {
    const t = setup("g_pro");
    await goRoundTrip(t);
    await t.flows.onAnalysis(empty(), t.cs(SITE));
    expect(t.opened).toEqual([]);
  });

  it("nothing while the site still shows a sign-in form", async () => {
    const t = setup();
    await goRoundTrip(t);
    await t.flows.onAnalysis(empty([{ ref: "f", kind: "login", fields: [{ ref: "p", role: "current_password" }] }]), t.cs(SITE));
    expect(t.opened).toEqual([]);
  });

  it("nothing past 5 minutes", async () => {
    const t = setup();
    await goRoundTrip(t);
    t.clock.t += PROVIDER_FLOW_TTL_MS + 1;
    await t.flows.onAnalysis(empty(), t.cs(SITE));
    expect(t.opened).toEqual([]);
  });

  it("a look-alike host is not the provider", async () => {
    const t = setup();
    await t.flows.onProviderClick(t.cs(SITE), "google");
    await t.flows.onNavigation(7, "https://accounts.google.com.evil.test/auth");
    await t.flows.onNavigation(7, `${SITE}/callback`);
    await t.flows.onAnalysis(empty(), t.cs(SITE));
    expect(t.opened).toEqual([]);
  });

  it("an account click outside the provider's hosts is ignored; one account is used as is", async () => {
    const t = setup(undefined, [acct("g_perso", "alex.perso@example.com")]);
    await t.flows.onProviderClick(t.cs(SITE), "google");
    await t.flows.onNavigation(7, `${GOOGLE}/chooser`);
    await t.flows.onAccountClick(t.cs("https://evil.test"), "someone@evil.test");
    await t.flows.onAnalysis(empty(), t.cs(SITE));
    expect(t.opened[0]?.provider).toEqual({ id: "google", accountItemId: "g_perso", email: "alex.perso@example.com" });
  });

  it("an email matching no account proposes nothing", async () => {
    const t = setup();
    await goRoundTrip(t, "nobody@example.com");
    await t.flows.onAnalysis(empty(), t.cs(SITE));
    expect(t.opened).toEqual([]);
  });

  it("subframe clicks are ignored", async () => {
    const t = setup();
    await t.flows.onProviderClick(t.cs(SITE, 2), "google");
    expect(await t.flows.signingInto(7, GOOGLE)).toBeNull();
  });

  it("signingInto names the site on the provider's pages", async () => {
    const t = setup();
    await t.flows.onProviderClick(t.cs(SITE), "google");
    await t.flows.onNavigation(7, `${GOOGLE}/chooser`);
    expect(await t.flows.signingInto(7, GOOGLE)).toEqual({ provider: "google", siteOrigin: SITE });
    expect(await t.flows.signingInto(7, "https://evil.test")).toBeNull();
  });
});
