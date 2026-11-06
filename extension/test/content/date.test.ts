// Birth dates as the page wants them (one-click signup, spec 5): the vault
// holds `YYYY-MM-DD`; the filler writes a date input, one part, or the
// written format of the field.
import { afterEach, describe, expect, it } from "vitest";
import { birthdayOption, birthdayPart, birthdayText } from "../../src/content/date";

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
