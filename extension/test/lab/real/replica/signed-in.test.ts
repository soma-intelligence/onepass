// Signed-in variant: no sign-in entry point or form left, an account cluster
// with a sign-out control in the site's language inside the site's header.
import { describe, expect, it } from "vitest";
import { labelsFor, makeSignedIn } from "../../../../lab/real/replica/signed-in.ts";

const doc = (html: string): Document => new DOMParser().parseFromString(html, "text/html");
const HOME = `<html lang="fr-FR"><head></head><body>
  <header><nav><ul><li><a href="/produits">Produits</a></li><li><a href="/connexion">Se connecter</a></li><li><a href="/signup">Créer un compte</a></li></ul></nav>
  <button>Connexion</button><a href="https://accounts.example.com/x">Mon espace</a></header>
  <main><form><input type="email"><input type="password"><button>OK</button></form><a href="/aide">Aide</a><form><input type="search" name="q"></form></main></body></html>`;

describe("signed-in variant", () => {
  it("removes every sign-in entry point and sign-in form, keeps the rest", () => {
    const r = makeSignedIn(HOME, { url: "https://www.example.com/" });
    const d = doc(r.html);
    const texts = Array.from(d.querySelectorAll("a, button")).map((e) => e.textContent!.trim());
    expect(texts).not.toContain("Se connecter");
    expect(texts).not.toContain("Créer un compte");
    expect(texts).not.toContain("Connexion");
    expect(texts).not.toContain("Mon espace");
    expect(texts).toContain("Produits");
    expect(texts).toContain("Aide");
    expect(d.querySelector("input[type=password]")).toBeNull();
    expect(d.querySelector("input[type=search]")).not.toBeNull();
  });

  it("puts the account cluster in the header, in the page language", () => {
    const r = makeSignedIn(HOME, { url: "https://www.example.com/" });
    const d = doc(r.html);
    expect(r.placement).toBe("header");
    expect(r.lang).toBe("fr");
    const cluster = d.querySelector('header [data-onepass-lab="signed-in"]')!;
    expect(cluster).not.toBeNull();
    expect(cluster.querySelector("summary[aria-haspopup=menu]")!.textContent).toContain("AM");
    const out = cluster.querySelector("[data-onepass-lab-signout]")!;
    expect(out.textContent).toBe("Se déconnecter");
    expect(out.getAttribute("href")).toBe("/logout");
    expect(d.querySelector('meta[name="onepass-lab-variant"]')!.getAttribute("content")).toBe("signed-in");
  });

  it("adds a top bar when the page has no header", () => {
    const r = makeSignedIn(`<html><body><p>x</p><a href="/login">Log in</a></body></html>`, { url: "https://x.com/", lang: "de" });
    const d = doc(r.html);
    expect(r.placement).toBe("bar");
    expect(d.body.firstElementChild!.getAttribute("data-onepass-lab")).toBe("signed-in");
    expect(d.querySelector("[data-onepass-lab-signout]")!.textContent).toBe("Abmelden");
    expect(Array.from(d.querySelectorAll("a")).some((a) => a.textContent === "Log in")).toBe(false);
  });

  it("falls back to English", () => {
    expect(labelsFor(undefined).signOut).toBe("Sign out");
    expect(labelsFor("xx").signOut).toBe("Sign out");
    expect(labelsFor("es-MX").signOut).toBe("Cerrar sesión");
  });
});

describe("account cluster placement", () => {
  it("takes the place of the header's sign-in link", () => {
    const r = makeSignedIn(`<html><body><header><div class="row"><a href="/a">A</a><a href="/login">Sign in</a></div></header></body></html>`, { url: "https://x.com/" });
    const d = new DOMParser().parseFromString(r.html, "text/html");
    expect(d.querySelector(".row > [data-onepass-lab-slot] > [data-onepass-lab=signed-in]")).not.toBeNull();
  });
});

describe("captured visibility marks", () => {
  it("prefers the sign-in control the capture saw on screen", () => {
    const html = `<html><body><header><nav class="mobile"><a href="/login">Sign in</a></nav><div class="desk"><a href="/login" data-onepass-lab-vis="">Sign in</a></div></header></body></html>`;
    const r = makeSignedIn(html, { url: "https://x.com/" });
    const d = new DOMParser().parseFromString(r.html, "text/html");
    expect(d.querySelector(".desk [data-onepass-lab=signed-in]")).not.toBeNull();
    expect(d.querySelector(".mobile a")).toBeNull();
    expect(d.querySelector("[data-onepass-lab-vis]")).toBeNull();
  });
});
