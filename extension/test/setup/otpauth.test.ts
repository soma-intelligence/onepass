import { describe, expect, it } from "vitest";
import { pastedSecret, shallowOtpauth } from "../../src/setup/otpauth";

const SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("shallowOtpauth", () => {
  it("accepts a plain setup URI", () => {
    const uri = `otpauth://totp/Atlas:ada@atlas-cloud.test?secret=${SECRET}&issuer=Atlas`;
    expect(shallowOtpauth(uri)).toEqual({ uri, issuer: "Atlas", account: "ada@atlas-cloud.test" });
  });

  it("accepts lowercase base32, padding, and an encoded label with a colon", () => {
    const uri = "otpauth://TOTP/Atlas%3Aada%40atlas-cloud.test?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq======";
    const r = shallowOtpauth(uri);
    expect(r).not.toBeNull();
    expect(r?.issuer).toBe("Atlas");
    expect(r?.account).toBe("ada@atlas-cloud.test");
    expect(shallowOtpauth(`OTPAUTH://totp/x?secret=${SECRET}`)).not.toBeNull();
  });

  it("takes the issuer parameter over the label prefix", () => {
    const r = shallowOtpauth(`otpauth://totp/Old:ada?secret=${SECRET}&issuer=New`);
    expect(r?.issuer).toBe("New");
    expect(r?.account).toBe("ada");
  });

  it("refuses hotp, otpauth-migration, https, a missing or short secret, and 2049 chars", () => {
    expect(shallowOtpauth(`otpauth://hotp/a?secret=${SECRET}&counter=1`)).toBeNull();
    expect(shallowOtpauth("otpauth-migration://offline?data=CjQKFDEy")).toBeNull();
    expect(shallowOtpauth(`https://example.test/?secret=${SECRET}`)).toBeNull();
    expect(shallowOtpauth("otpauth://totp/a:b?issuer=a")).toBeNull();
    expect(shallowOtpauth("otpauth://totp/a:b?secret=GEZDGNBVGY3TQ")).toBeNull();
    const base = `otpauth://totp/a?secret=${SECRET}&issuer=`;
    expect(shallowOtpauth(base + "x".repeat(2048 - base.length))).not.toBeNull();
    expect(shallowOtpauth(base + "x".repeat(2049 - base.length))).toBeNull();
  });
});

describe("pastedSecret", () => {
  it("drops spaces and dashes and refuses non-base32", () => {
    expect(pastedSecret("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq")).toBe(SECRET);
    expect(pastedSecret(`  ${SECRET}\n`)).toBe(SECRET);
    expect(pastedSecret("GEZDGNBVGY3TQ")).toBeNull();
    expect(pastedSecret("GEZDGNBVGY3TQOJ1")).toBeNull();
    expect(pastedSecret("hello world, this is not a key")).toBeNull();
  });
});
