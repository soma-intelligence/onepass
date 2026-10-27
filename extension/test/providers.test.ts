import { describe, expect, it } from "vitest";
import { PROVIDERS, providerForHost, providerFromButtonText } from "../src/shared/providers";

describe("PROVIDERS", () => {
  it("lists the nine providers with exact hosts", () => {
    expect(PROVIDERS.map((p) => p.id)).toEqual([
      "google", "apple", "microsoft", "github", "facebook", "x", "linkedin", "discord", "slack",
    ]);
    expect(PROVIDERS.find((p) => p.id === "x")?.hosts).toEqual(["x.com", "twitter.com", "api.x.com"]);
  });
});

describe("providerForHost", () => {
  it("matches exact hosts, case-insensitively", () => {
    expect(providerForHost("accounts.google.com")).toBe("google");
    expect(providerForHost("ACCOUNTS.Google.com")).toBe("google");
    expect(providerForHost("idmsa.apple.com")).toBe("apple");
    expect(providerForHost("login.live.com")).toBe("microsoft");
    expect(providerForHost("github.com")).toBe("github");
    expect(providerForHost("m.facebook.com")).toBe("facebook");
    expect(providerForHost("twitter.com")).toBe("x");
    expect(providerForHost("www.linkedin.com")).toBe("linkedin");
    expect(providerForHost("discord.com")).toBe("discord");
    expect(providerForHost("slack.com")).toBe("slack");
  });
  it("rejects look-alikes and non-listed subdomains", () => {
    expect(providerForHost("accounts.google.com.evil.test")).toBeNull();
    expect(providerForHost("evil-accounts.google.com")).toBeNull();
    expect(providerForHost("accounts.google.com.")).toBe("google");
    expect(providerForHost("google.com")).toBeNull();
    expect(providerForHost("mail.google.com")).toBeNull();
    expect(providerForHost("sub.github.com")).toBeNull();
    expect(providerForHost("xn--ccounts-ugc.google.com")).toBeNull();
    expect(providerForHost("")).toBeNull();
  });
});

describe("providerFromButtonText", () => {
  it.each([
    ["Continuer avec Google", "google"],
    ["Se connecter avec Apple", "apple"],
    ["Sign in with Microsoft", "microsoft"],
    ["Continue with GitHub", "github"],
    ["Log in with Facebook", "facebook"],
    ["CONTINUE WITH LINKEDIN", "linkedin"],
    ["sign in with discord", "discord"],
    ["Continuer avec Slack", "slack"],
    ["Continue with X", "x"],
    ["Sign in with Twitter", "x"],
    ["Se connecter avec X", "x"],
    ["  Continue   with   Google  ", "google"],
    ["Continue with Google.", "google"],
    ["Continuer avec votre compte Google", "google"],
    ["Sign in with your Apple ID", "apple"],
  ] as const)("%s -> %s", (text, id) => {
    expect(providerFromButtonText(text)).toBe(id);
  });
  it.each([
    "Continue with email",
    "Continue with Xbox",
    "Sign in with example",
    "Se connecter",
    "Google",
    "Sign in with a passkey",
    "Continue with phone x",
    "",
  ])("%j -> null", (text) => {
    expect(providerFromButtonText(text)).toBeNull();
  });
});
