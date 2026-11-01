// Country and region lists, filled like a person would (spec 2026-10-31).
import { afterEach, describe, expect, it } from "vitest";
import { analyzeDocument } from "../../src/content/detect/forms";
import { RefRegistry } from "../../src/content/detect/refs";
import { createFiller } from "../../src/content/filler";
import type { FieldRole } from "../../src/shared/messages";
import { testGeometry } from "../detect/helpers";

const SITE = "https://shop.test/checkout";
type Values = Partial<Record<FieldRole, string>>;

const sel = (id: string) => document.getElementById(id) as HTMLSelectElement;
const inp = (id: string) => document.getElementById(id) as HTMLInputElement;
const selectedText = (id: string) => sel(id).selectedOptions[0]?.textContent ?? "";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const timers: ReturnType<typeof setTimeout>[] = [];
const later = (fn: () => void, ms: number) => timers.push(setTimeout(fn, ms));

afterEach(() => {
  for (const t of timers.splice(0)) clearTimeout(t);
  document.documentElement.lang = "";
  document.body.innerHTML = "";
});

function setup(html: string, settleMs = 400) {
  document.body.innerHTML = html;
  const refs = new RefRegistry();
  const analyze = () => analyzeDocument(document, refs, { url: SITE, geometry: testGeometry });
  const filler = createFiller({
    refs,
    geometry: testGeometry,
    analyze,
    resolve: (ref, a) => a.forms.find((f) => f.ref === ref) ?? null,
    settleMs,
  });
  const fill = (values: Values) => filler.fillForm(analyze().forms[0]!.ref, values);
  const fillAll = (values: Values) => filler.fill(analyze().forms[0]!.ref, values);
  return { filler, fill, fillAll };
}

const ADDRESS = (country: string, region: string) => `
<form id="f">
  <label for="a1">Address</label><input id="a1" autocomplete="address-line1">
  <label for="zip">ZIP code</label><input id="zip" autocomplete="postal-code">
  <label for="city">City</label><input id="city" autocomplete="address-level2">
  ${country}
  ${region}
  <button type="submit">Continue</button>
</form>`;

const US_STATES = `<option value="">State</option><option value="CA">California</option><option value="NY">New York</option><option value="OR">Oregon</option>`;
const FR_DEPTS = `<option value="">Département</option><option value="69">69 - Rhône</option><option value="75">75 - Paris</option>`;

describe("country lists", () => {
  it("picks the name for an ISO code", () => {
    const { fill } = setup(ADDRESS(
      `<label for="c">Country</label><select id="c" autocomplete="country"><option value="">Country</option><option value="1">Germany</option><option value="2">France</option></select>`, ""));
    expect(fill({ address_line1: "1 rue Neuve", country: "FR" })).toBe(2);
    expect(sel("c").value).toBe("2");
  });

  it("reads names in the page language", () => {
    document.documentElement.lang = "de";
    const { fill } = setup(ADDRESS(
      `<label for="c">Land</label><select id="c" autocomplete="country"><option>Frankreich</option><option>Deutschland</option></select>`, ""));
    fill({ country: "DE" });
    expect(sel("c").value).toBe("Deutschland");
  });

  it("leaves a list that already shows the country alone (no change event)", () => {
    const { fill } = setup(ADDRESS(
      `<label for="c">Country</label><select id="c" autocomplete="country"><option value="FR">France</option><option value="US" selected>United States</option></select>`, ""));
    let changes = 0;
    sel("c").addEventListener("change", () => changes++);
    expect(fill({ address_line1: "1 Harbor Road", country: "US" })).toBe(2);
    expect(changes).toBe(0);
  });

  it("writes nothing on a tie", () => {
    const { fill } = setup(ADDRESS(
      `<label for="c">Country</label><select id="c" autocomplete="country"><option value="">-</option><option value="a">United States</option><option value="b">USA</option></select>`, ""));
    expect(fill({ country: "US" })).toBe(0);
    expect(sel("c").value).toBe("");
  });

  it("writes the country name into a country-name text field", () => {
    document.documentElement.lang = "fr";
    const { fill } = setup(ADDRESS(`<label for="c">Pays</label><input id="c" autocomplete="country-name">`, ""));
    fill({ country: "DE" });
    expect(inp("c").value).toBe("Allemagne");
  });
});

describe("region lists", () => {
  it("fills at once when the list is already the right one", () => {
    const { fill } = setup(ADDRESS(
      `<label for="c">Country</label><select id="c" autocomplete="country"><option value="US">United States</option></select>`,
      `<label for="s">State</label><select id="s" autocomplete="address-level1">${US_STATES}</select>`));
    expect(fill({ country: "US", region: "US-CA" })).toBe(2);
    expect(sel("s").value).toBe("CA");
  });

  it("waits for the list a country change reloads", async () => {
    const { fill, filler } = setup(ADDRESS(
      `<label for="c">Country</label><select id="c" autocomplete="country"><option value="US">United States</option><option value="FR">France</option></select>`,
      `<label for="s">State</label><select id="s" autocomplete="address-level1">${US_STATES}</select>`));
    sel("c").addEventListener("change", () => {
      // The shop fetches the departments, then replaces the options.
      later(() => (sel("s").innerHTML = FR_DEPTS), 60);
    });
    expect(fill({ country: "FR", region: "Rhone" })).toBe(1);
    expect(sel("s").value).toBe("");
    await filler.settled();
    expect(sel("s").value).toBe("69");
  });

  it("waits for a region field that appears with the country", async () => {
    const { fill, filler } = setup(ADDRESS(
      `<label for="c">Country</label><select id="c" autocomplete="country"><option value="GB">United Kingdom</option><option value="CA">Canada</option></select>`,
      `<div id="slot"></div>`));
    sel("c").addEventListener("change", () => {
      later(() => {
        document.getElementById("slot")!.innerHTML =
          `<label for="p">Province</label><select id="p" autocomplete="address-level1"><option value="">Province</option><option value="ON">Ontario</option><option value="QC">Québec</option></select>`;
      }, 50);
    });
    fill({ country: "CA", region: "Quebec" });
    await filler.settled();
    expect(sel("p").value).toBe("QC");
  });

  it("gives up after the bound and leaves the list alone", async () => {
    const { fill, filler } = setup(ADDRESS(
      `<label for="c">Country</label><select id="c" autocomplete="country"><option value="US">United States</option><option value="FR">France</option></select>`,
      `<label for="s">State</label><select id="s" autocomplete="address-level1">${US_STATES}</select>`), 120);
    const t0 = Date.now();
    fill({ country: "FR", region: "Rhone" });
    await filler.settled();
    expect(Date.now() - t0).toBeLessThan(1000);
    expect(sel("s").value).toBe("");
  });

  it("deduces the state from the ZIP code", () => {
    const { fill } = setup(ADDRESS(
      `<label for="c">Country</label><select id="c" autocomplete="country"><option value="US">United States</option></select>`,
      `<label for="s">State</label><select id="s" autocomplete="address-level1">${US_STATES}</select>`));
    fill({ country: "US", postal_code: "97201" });
    expect(sel("s").value).toBe("OR");
    expect(inp("zip").value).toBe("97201");
  });

  it("deduces a Corsican department from the postal code", () => {
    const { fill } = setup(ADDRESS(
      `<label for="c">Pays</label><select id="c" autocomplete="country"><option value="FR">France</option></select>`,
      `<label for="d">Département</label><select id="d" autocomplete="address-level1"><option value="">-</option><option value="2A">Corse-du-Sud</option><option value="2B">Haute-Corse</option></select>`));
    fill({ country: "FR", postal_code: "20200" });
    expect(sel("d").value).toBe("2B");
  });

  it("a region the list does not have falls back on a consistent postal code", () => {
    const html = ADDRESS(
      `<label for="c">Pays</label><select id="c" autocomplete="country"><option value="FR">France</option></select>`,
      `<label for="d">Département</label><select id="d" autocomplete="address-level1">${FR_DEPTS}</select>`);
    setup(html).fill({ country: "FR", region: "Île-de-France", postal_code: "75008" });
    expect(sel("d").value).toBe("75");
    // A postal code from another region is not trusted.
    setup(html).fill({ country: "FR", region: "Bretagne", postal_code: "75008" });
    expect(sel("d").value).toBe("");
  });

  it("never deduces into a text field", () => {
    const { fill } = setup(ADDRESS("", `<label for="s">State</label><input id="s" autocomplete="address-level1">`));
    fill({ postal_code: "97201", country: "US" });
    expect(inp("s").value).toBe("");
  });

  it("writes a canonical region into a text field as people do", () => {
    const { fill } = setup(ADDRESS("", `<label for="s">State</label><input id="s" autocomplete="address-level1">`));
    fill({ region: "US-CA" });
    expect(inp("s").value).toBe("CA");
  });

  it("reads the country of the page's list when the item has none", () => {
    const { fill } = setup(ADDRESS(
      `<label for="c">Pays</label><select id="c" autocomplete="country"><option value="FR" selected>France</option></select>`,
      `<label for="d">Département</label><select id="d" autocomplete="address-level1">${FR_DEPTS}</select>`));
    fill({ postal_code: "75008" });
    expect(sel("d").value).toBe("75");
  });

  it("a tie between two states writes nothing", () => {
    const { fill } = setup(ADDRESS(
      `<label for="c">Country</label><select id="c" autocomplete="country"><option value="US">United States</option></select>`,
      `<label for="s">State</label><select id="s" autocomplete="address-level1"><option value="">-</option><option value="5">California</option><option value="6">CA - California</option></select>`));
    fill({ country: "US", region: "CA" });
    expect(sel("s").value).toBe("");
  });
});

/**
 * A React-select style widget: a text input `role=combobox`, a listbox
 * rendered after each keystroke (asynchronously), an option click that shows
 * the choice. `hidden` adds a native select behind it that the widget itself
 * never updates.
 */
function combobox(id: string, label: string, choices: [string, string][], opts: { hidden?: boolean; delay?: number } = {}): string {
  return `<div class="rs" id="${id}-box"><label for="${id}">${label}</label>
    <input id="${id}" role="combobox" aria-autocomplete="list" aria-expanded="false" aria-controls="${id}-list" autocomplete="off" data-choices='${JSON.stringify(choices)}' data-delay="${opts.delay ?? 15}">
    <div class="rs-value" id="${id}-value"></div>
    ${opts.hidden ? `<select id="${id}-native" name="${id}" style="display:none"><option value=""></option>${choices.map(([v, t]) => `<option value="${v}">${t}</option>`).join("")}</select>` : ""}
  </div>`;
}

function wireCombobox(id: string): string[] {
  const clicked: string[] = [];
  const input = inp(id);
  const choices = JSON.parse(input.dataset.choices!) as [string, string][];
  const delay = Number(input.dataset.delay);
  input.addEventListener("input", () => {
    const q = input.value.toLowerCase();
    later(() => {
      document.getElementById(`${id}-list`)?.remove();
      const list = document.createElement("div");
      list.id = `${id}-list`;
      list.setAttribute("role", "listbox");
      for (const [v, t] of choices.filter(([, t]) => t.toLowerCase().includes(q))) {
        const o = document.createElement("div");
        o.setAttribute("role", "option");
        o.dataset.value = v;
        o.textContent = t;
        o.addEventListener("click", () => {
          clicked.push(v);
          document.getElementById(`${id}-value`)!.textContent = t;
          input.value = "";
          list.remove();
        });
        list.append(o);
      }
      input.setAttribute("aria-expanded", "true");
      document.body.append(list); // a portal, as React-select menus often are
    }, delay);
  });
  return clicked;
}

describe("ARIA comboboxes", () => {
  it("types the name and picks the option, then the region after it", async () => {
    const { fill, filler } = setup(ADDRESS(
      combobox("c", "Country", [["US", "United States"], ["FR", "France"], ["DE", "Germany"]]),
      combobox("s", "State", [["CA", "California"], ["OR", "Oregon"]])));
    const pickedCountry = wireCombobox("c");
    const pickedState = wireCombobox("s");
    expect(fill({ country: "FR", region: "Oregon" })).toBe(0);
    await filler.settled();
    expect(pickedCountry).toEqual(["FR"]);
    expect(pickedState).toEqual(["OR"]);
    expect(document.getElementById("c-value")!.textContent).toBe("France");
  });

  it("fills the hidden select behind the widget, and no other hidden field", async () => {
    const { fill, filler } = setup(`${ADDRESS(combobox("c", "Country", [["US", "United States"], ["FR", "France"]], { hidden: true }), "")}`
      .replace("</form>", `<select id="trap" name="trap" style="display:none"><option value=""></option><option value="FR">France</option></select></form>`));
    wireCombobox("c");
    fill({ country: "FR" });
    await filler.settled();
    expect(sel("c-native").value).toBe("FR");
    expect(sel("trap").value).toBe("");
  });

  it("types another name when the first one filters every option out", async () => {
    const { fill, filler } = setup(ADDRESS(
      combobox("c", "Country", [["DE", "Germany"], ["FR", "France"]]),
      combobox("s", "State", [["BY", "Bavaria"], ["BE", "Berlin"]])));
    wireCombobox("c");
    const picked = wireCombobox("s");
    fill({ country: "DE", region: "Bayern" });
    await filler.settled();
    expect(picked).toEqual(["BY"]);
  });

  it("never presses an option that is or holds a button or a link", async () => {
    const { fill, filler } = setup(ADDRESS(`<label for="c">Country</label>
      <input id="c" role="combobox" aria-controls="menu"><div role="listbox" id="menu">
      <button role="option" type="submit" id="buy">France</button></div>
      <input id="r" role="combobox" aria-controls="menu2" aria-label="State"><div role="listbox" id="menu2">
      <a role="option" href="/pay" id="pay">Oregon</a></div>`, ""), 150);
    let clicks = 0;
    document.getElementById("buy")!.addEventListener("click", (e) => (e.preventDefault(), clicks++));
    document.getElementById("pay")!.addEventListener("click", (e) => (e.preventDefault(), clicks++));
    fill({ country: "FR", region: "OR" });
    await filler.settled();
    expect(clicks).toBe(0);
  });

  it("does not click anything when the list never shows the value, and counts nothing", async () => {
    const { fill, filler } = setup(ADDRESS(combobox("c", "Country", [["US", "United States"]]), ""), 150);
    const picked = wireCombobox("c");
    expect(fill({ country: "FR" })).toBe(0);
    await filler.settled();
    expect(picked).toEqual([]);
  });

  it("a combobox counts only once an option is picked; typed text is restored", async () => {
    const page = ADDRESS(combobox("c", "Country", [["US", "United States"], ["FR", "France"]]), "");
    let t = setup(page, 150);
    wireCombobox("c");
    let r = t.fillAll({ country: "FR" });
    expect(r.now).toBe(0);
    expect(await r.done).toEqual(["country"]);

    t = setup(page.replace(`["FR","France"]`, `["DE","Germany"]`), 150);
    const picked = wireCombobox("c");
    inp("c").value = "";
    r = t.fillAll({ country: "FR" });
    expect(r.now).toBe(0);
    expect(await r.done).toEqual([]);
    expect(picked).toEqual([]);
    expect(inp("c").value).toBe("");
  });
});
