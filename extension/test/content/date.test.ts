// Birth dates as the page wants them (one-click signup, spec 5): the vault
// holds `YYYY-MM-DD`; the filler writes a date input, one part, or the
// written format of the field.
import { afterEach, describe, expect, it } from "vitest";
import { birthdayOption, birthdayPart, birthdayText, dateOption, datePart, dateText, monthOf } from "../../src/content/date";

const ISO = "1990-04-07";

function el<K extends keyof HTMLElementTagNameMap>(html: string): HTMLElementTagNameMap[K] {
  document.body.innerHTML = html;
  return document.body.querySelector("[data-t]") as HTMLElementTagNameMap[K];
}

afterEach(() => {
  document.body.innerHTML = "";
});

describe("birthdayText", () => {
  it("a date input gets the ISO date", () => {
    expect(birthdayText(el<"input">('<input data-t type="date">'), ISO, "fr")).toBe("1990-04-07");
  });

  it("a written format in the placeholder", () => {
    expect(birthdayText(el<"input">('<input data-t placeholder="JJ/MM/AAAA">'), ISO, "fr")).toBe("07/04/1990");
    expect(birthdayText(el<"input">('<input data-t placeholder="MM/DD/YYYY">'), ISO, "en")).toBe("04/07/1990");
    expect(birthdayText(el<"input">('<input data-t placeholder="TT.MM.JJJJ">'), ISO, "de")).toBe("07.04.1990");
    expect(birthdayText(el<"input">('<input data-t placeholder="yyyy-mm-dd">'), ISO, "en")).toBe("1990-04-07");
    expect(birthdayText(el<"input">('<input data-t placeholder="D/M/YYYY">'), ISO, "en-GB")).toBe("7/4/1990");
  });

  it("without a format, the page's language", () => {
    expect(birthdayText(el<"input">("<input data-t>"), ISO, "en-US")).toBe("04/07/1990");
    expect(birthdayText(el<"input">("<input data-t>"), ISO, "en")).toBe("04/07/1990");
    expect(birthdayText(el<"input">("<input data-t>"), ISO, "en-GB")).toBe("07/04/1990");
    expect(birthdayText(el<"input">("<input data-t>"), ISO, "fr")).toBe("07/04/1990");
    expect(birthdayText(el<"input">("<input data-t>"), ISO, null)).toBe("07/04/1990");
  });

  it("one part of a split date", () => {
    expect(birthdayText(el<"input">('<input data-t autocomplete="bday-year">'), ISO, "fr")).toBe("1990");
    expect(birthdayText(el<"input">('<input data-t autocomplete="bday-month">'), ISO, "fr")).toBe("04");
    expect(birthdayText(el<"input">('<input data-t name="dob_day" maxlength="2">'), ISO, "fr")).toBe("07");
    expect(birthdayText(el<"input">('<input data-t placeholder="AAAA">'), ISO, "fr")).toBe("1990");
  });

  it("a value that is not a date stays out", () => {
    expect(birthdayText(el<"input">("<input data-t>"), "7 avril", "fr")).toBeNull();
  });

  it("a field named birthDay is the whole date, not a day", () => {
    expect(birthdayPart(el<"input">('<input data-t name="birthDay">'))).toBeNull();
  });
});

describe("birthdayOption", () => {
  const days = `<select data-t name="day"><option value="">Jour</option>${Array.from({ length: 31 }, (_, i) => `<option value="${i + 1}">${i + 1}</option>`).join("")}</select>`;
  const months = `<select data-t><option value="">Mois</option>${["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"].map((m, i) => `<option value="m${i}">${m}</option>`).join("")}</select>`;
  const years = `<select data-t><option value="">Année</option>${Array.from({ length: 100 }, (_, i) => `<option>${2025 - i}</option>`).join("")}</select>`;

  it("three lists: day, month by name, year", () => {
    const d = el<"select">(days);
    expect(d.options[birthdayOption(d, ISO)]?.value).toBe("7");
    const m = el<"select">(months);
    expect(birthdayPart(m)).toBe("month");
    expect(m.options[birthdayOption(m, ISO)]?.value).toBe("m3");
    const y = el<"select">(years);
    expect(birthdayPart(y)).toBe("year");
    expect(y.options[birthdayOption(y, ISO)]?.textContent).toBe("1990");
  });

  it("a day list with leading zeros", () => {
    const d = el<"select">(`<select data-t autocomplete="bday-day">${Array.from({ length: 31 }, (_, i) => `<option value="${String(i + 1).padStart(2, "0")}">${i + 1}</option>`).join("")}</select>`);
    expect(d.options[birthdayOption(d, ISO)]?.value).toBe("07");
  });

  it("a list it cannot read: nothing chosen", () => {
    const s = el<"select">('<select data-t><option>Rouge</option><option>Vert</option></select>');
    expect(birthdayOption(s, ISO)).toBe(-1);
  });
});

// Forms coverage, Task 10: the same rules for every date role, seven languages.
describe("dateText, datePart, dateOption (forms coverage)", () => {
  it("written formats of the seven languages", () => {
    const t = (ph: string, lang: string) => dateText(el<"input">(`<input data-t placeholder="${ph}">`), ISO, lang);
    expect(t("JJ/MM/AAAA", "fr")).toBe("07/04/1990");
    expect(t("MM/DD/YYYY", "en")).toBe("04/07/1990");
    expect(t("TT.MM.JJJJ", "de")).toBe("07.04.1990");
    expect(t("DD.MM.YYYY", "de")).toBe("07.04.1990");
    expect(t("gg/mm/aaaa", "it")).toBe("07/04/1990");
    expect(t("dd/mm/aaaa", "pt")).toBe("07/04/1990");
    expect(t("dd-mm-jjjj", "nl")).toBe("07-04-1990");
    expect(t("AAAA-MM-JJ", "fr")).toBe("1990-04-07");
  });

  it("without a format, the order of the page's language", () => {
    const t = (lang: string) => dateText(el<"input">("<input data-t>"), "1990-04-12", lang);
    expect(t("en-US")).toBe("04/12/1990");
    expect(t("en")).toBe("04/12/1990");
    expect(t("fr")).toBe("12/04/1990");
    expect(t("de")).toBe("12.04.1990");
    expect(t("de-AT")).toBe("12.04.1990");
    expect(t("nl")).toBe("12-04-1990");
    expect(t("es")).toBe("12/04/1990");
    expect(t("it")).toBe("12/04/1990");
    expect(t("pt-BR")).toBe("12/04/1990");
  });

  it("a year box of two characters gets two digits", () => {
    expect(dateText(el<"input">('<input data-t autocomplete="bday-year" maxlength="2">'), ISO, "fr")).toBe("90");
    expect(dateText(el<"input">('<input data-t name="exp_year" maxlength="2" aria-label="Year">'), ISO, "en")).toBe("90");
  });

  it("part words of the seven languages", () => {
    const p = (label: string) => datePart(el<"input">(`<label for="x">${label}</label><input data-t id="x">`));
    expect(["Jour", "Day", "Tag", "Día", "Giorno", "Dia", "Dag"].map(p)).toEqual(Array(7).fill("day"));
    expect(["Mois", "Month", "Monat", "Mes", "Mese", "Mês", "Maand"].map(p)).toEqual(Array(7).fill("month"));
    expect(["Année", "Year", "Jahr", "Año", "Anno", "Ano", "Jaar"].map(p)).toEqual(Array(7).fill("year"));
  });

  it("month names of the seven languages, abbreviations too", () => {
    const names = ["avril", "April", "April", "abril", "aprile", "abril", "april", "avr.", "Apr", "Apr.", "abr", "apr"];
    for (const n of names) expect(monthOf(n), n).toBe(4);
    expect(["janv.", "Jan", "Jän", "ene", "gen", "jan"].map(monthOf)).toEqual(Array(6).fill(1));
    expect(["Mär", "März", "mrt", "maart", "marzo", "março", "mar"].map(monthOf)).toEqual(Array(7).fill(3));
    expect(["fév", "fev", "Feb", "feb", "febrero", "febbraio", "fevereiro", "februari"].map(monthOf)).toEqual(Array(8).fill(2));
    expect(["mai", "Mai", "mayo", "maggio", "maio", "mei", "May"].map(monthOf)).toEqual(Array(7).fill(5));
    expect(["déc.", "Dez", "dic", "dez", "dec", "diciembre", "dicembre", "dezembro", "december"].map(monthOf)).toEqual(Array(9).fill(12));
  });

  it("a month list in each language, abbreviated", () => {
    const list = (names: string[]) => el<"select">(`<select data-t>${names.map((m, i) => `<option value="${i + 1}">${m}</option>`).join("")}</select>`);
    const langs = [
      ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"],
      ["gen", "feb", "mar", "apr", "mag", "giu", "lug", "ago", "set", "ott", "nov", "dic"],
      ["jan", "fev", "mar", "abr", "mai", "jun", "jul", "ago", "set", "out", "nov", "dez"],
      ["jan", "feb", "mrt", "apr", "mei", "jun", "jul", "aug", "sep", "okt", "nov", "dec"],
      ["Jan", "Feb", "Mär", "Apr", "Mai", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dez"],
    ];
    for (const names of langs) {
      const s = list(names);
      expect(datePart(s), names.join()).toBe("month");
      expect(s.options[dateOption(s, ISO)]?.value, names.join()).toBe("4");
    }
  });

  it("a month input is never a birth or document date", () => {
    expect(dateText(el<"input">('<input data-t type="month">'), ISO, "fr")).toBeNull();
  });

  it("a year list of future years reads as a year (a passport expiry)", () => {
    const s = el<"select">(`<select data-t>${Array.from({ length: 15 }, (_, i) => `<option>${2026 + i}</option>`).join("")}</select>`);
    expect(datePart(s)).toBe("year");
    expect(s.options[dateOption(s, "2031-05-02")]?.textContent).toBe("2031");
  });
});
