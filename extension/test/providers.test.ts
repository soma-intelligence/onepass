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
    // Spanish, Italian, German, Portuguese, Dutch.
    ["Continuar con Google", "google"],
    ["Iniciar sesión con Apple", "apple"],
    ["Inicia sesión con tu cuenta de Microsoft", "microsoft"],
    ["Acceder con GitHub", "github"],
    ["Entrar con Facebook", "facebook"],
    ["Continua con Google", "google"],
    ["Accedi con Apple", "apple"],
    ["Accedi con il tuo account Microsoft", "microsoft"],
    ["Entra con X", "x"],
    ["Weiter mit Google", "google"],
    ["Anmelden mit Apple", "apple"],
    ["Mit Google anmelden", "google"],
    ["Mit Ihrem Microsoft-Konto anmelden", "microsoft"],
    ["Mit Apple fortfahren", "apple"],
    ["Über GitHub anmelden", "github"],
    ["Continuar com Google", "google"],
    ["Entrar com o Google", "google"],
    ["Iniciar sessão com a Apple", "apple"],
    ["Fazer login com sua conta Microsoft", "microsoft"],
    ["Doorgaan met Google", "google"],
    ["Inloggen met Apple", "apple"],
    ["Aanmelden met je Microsoft-account", "microsoft"],
    ["Log in met Discord", "discord"],
    ["Verder met Slack", "slack"],
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
    "Continuar con el correo",
    "Weiter mit E-Mail",
    "Mit Xbox anmelden",
    "Mit Google Maps anmelden",
    "Doorgaan met telefoon",
    "Continuar com Xbox",
    "Accedi con passkey",
    "Mit anmelden",
    "",
  ])("%j -> null", (text) => {
    expect(providerFromButtonText(text)).toBeNull();
  });
});
