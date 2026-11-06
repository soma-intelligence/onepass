// Forms coverage, Task 11: civility and sex lists and radio groups (spec section 7).
import { describe, expect, it } from "vitest";
import { canonicalCivility, canonicalSex, pickChoice } from "../../src/content/choice";

const o = (...xs: (string | [string, string])[]) => xs.map((x) => (typeof x === "string" ? { value: x, text: x } : { value: x[0], text: x[1] }));

describe("canonical values", () => {
  it("reads a sex in seven languages, folded, final dot ignored", () => {
    for (const s of ["Homme", "Masculin", "Male", "Männlich", "Hombre", "Maschio", "Masculino", "Man", "M", "H"]) expect(canonicalSex(s)).toBe("m");
    for (const s of ["Femme", "Féminin", "Female", "Weiblich", "Mujer", "Femmina", "Feminino", "Vrouw", "F"]) expect(canonicalSex(s)).toBe("f");
    for (const s of ["Autre", "Other", "Divers", "Otro", "Altro", "Outro", "Anders", "X"]) expect(canonicalSex(s)).toBe("x");
    expect(canonicalSex("Peut-être")).toBeNull();
  });

  it("reads a civility per its own table: Dr only Dr", () => {
    for (const s of ["M.", "Monsieur", "Mr", "Herr", "Sr.", "Sig.", "Dhr."]) expect(canonicalCivility(s)).toBe("mr");
    for (const s of ["Mme", "Madame", "Mrs", "Frau", "Sra.", "Sig.ra", "Mevr."]) expect(canonicalCivility(s)).toBe("mrs");
    for (const s of ["Mlle", "Miss", "Srta.", "Sig.na", "Menina", "Mej."]) expect(canonicalCivility(s)).toBe("miss");
    expect(canonicalCivility("Ms")).toBe("ms");
    expect(canonicalCivility("Mx")).toBe("mx");
    for (const s of ["Dr", "Dr.", "Docteur", "Dott."]) expect(canonicalCivility(s)).toBe("dr");
  });
});

describe("pickChoice", () => {
  it("picks the sex option by its label in each language, whatever the values", () => {
    expect(pickChoice(o(["", "--"], ["1", "Homme"], ["2", "Femme"]), "sex", { sex: "f" })).toBe(2);
    expect(pickChoice(o(["M", "Männlich"], ["W", "Weiblich"], ["D", "Divers"]), "sex", { sex: "x" })).toBe(2);
    expect(pickChoice(o(["H", "Hombre"], ["M", "Mujer"]), "sex", { sex: "f" })).toBe(1);
    expect(pickChoice(o("Maschio", "Femmina"), "sex", { sex: "m" })).toBe(0);
    expect(pickChoice(o("Man", "Vrouw"), "sex", { value: "Vrouw" })).toBe(1);
  });

  it("an M is a sex in a sex list and Monsieur in a civility list", () => {
    expect(pickChoice(o("M", "F"), "sex", { sex: "m" })).toBe(0);
    expect(pickChoice(o("M.", "Mme"), "honorific_prefix", { value: "Monsieur" })).toBe(0);
  });

  it("the vault's civility picks its own option; Dr matches Dr only", () => {
    expect(pickChoice(o("M.", "Mme", "Mlle", "Dr"), "honorific_prefix", { value: "Mme", sex: "f" })).toBe(1);
    expect(pickChoice(o("Mr", "Ms", "Mrs", "Miss"), "honorific_prefix", { value: "Ms" })).toBe(1);
    expect(pickChoice(o("Mr", "Ms", "Mrs"), "honorific_prefix", { value: "Dr", sex: "m" })).toBe(-1);
    expect(pickChoice(o("Herr", "Frau", "Dr."), "honorific_prefix", { value: "Dr" })).toBe(2);
  });

  it("without a civility, it comes from the sex: f picks Ms, else madame, never Miss nor Mlle", () => {
    expect(pickChoice(o("Mr", "Mrs", "Ms", "Miss"), "honorific_prefix", { sex: "f" })).toBe(2);
    expect(pickChoice(o("M.", "Mlle", "Mme"), "honorific_prefix", { sex: "f" })).toBe(2);
    expect(pickChoice(o("Mr", "Miss"), "honorific_prefix", { sex: "f" })).toBe(-1);
    expect(pickChoice(o("Herr", "Frau"), "honorific_prefix", { sex: "m" })).toBe(0);
    expect(pickChoice(o("Mr", "Ms", "Mx"), "honorific_prefix", { sex: "x" })).toBe(2);
    expect(pickChoice(o("Mr", "Ms"), "honorific_prefix", { sex: "x" })).toBe(-1);
  });

  it("two best options of different values: nothing", () => {
    expect(pickChoice(o(["a", "Femme"], ["b", "Féminin"]), "sex", { sex: "f" })).toBe(-1);
    expect(pickChoice(o(["a", "Mme"], ["b", "Madame"]), "honorific_prefix", { value: "Mrs" })).toBe(-1);
    // The vault's exact text wins over an option of the same civility.
    expect(pickChoice(o(["a", "Mme"], ["b", "Madame"]), "honorific_prefix", { value: "Mme" })).toBe(0);
  });

  it("a value code is read when the label says nothing", () => {
    expect(pickChoice(o(["MR", "1"], ["MRS", "2"]), "honorific_prefix", { value: "Mme" })).toBe(1);
  });
});
