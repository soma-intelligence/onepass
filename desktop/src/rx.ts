// The RX design of the Mac app, for Windows: the wallpaper sets of the Home hero
// (apple/App/Settings/RXWallpaperSettings.swift), the item's identity colour and
// its wash (apple/DesignKit/.../IdentityTint.swift), and the category colours.
import { t } from "./catalog";

// ---- wallpapers -------------------------------------------------------------------------------

export interface WallpaperTheme {
  key: string;
  name: string;
  tones: boolean;
}

/** In the order of the theme chips. lava, lights, silk, glass and landscape also come Noir and Clair. */
export const wallpaperThemes = (): WallpaperTheme[] => [
  { key: "landscape", name: t("Paysages", "Landscapes"), tones: true },
  { key: "glass", name: t("Verre", "Glass"), tones: true },
  { key: "silk", name: t("Soie", "Silk"), tones: true },
  { key: "metal", name: t("Métal", "Metal"), tones: false },
  { key: "lights", name: t("Lumières", "Lights"), tones: true },
  { key: "lava", name: t("Lave", "Lava"), tones: true },
  { key: "velvet", name: t("Velours", "Velvet"), tones: false },
  { key: "horizon", name: "Horizon", tones: false },
  { key: "particles", name: t("Particules", "Particles"), tones: false },
];

export type Tone = "" | "noir" | "clair";

export const wallpaperName = (theme: string, n: number, tone: Tone): string => `wp-${theme}-${n}${tone ? "-" + tone : ""}`;

/** The default of the Mac: Lava 3. */
export const DEFAULT_WALLPAPER = "wp-lava-3";
const KEY = "rx.home.wallpaper";

const LIGHT = new Set([
  "wp-metal-2", "wp-metal-3", "wp-velvet-1", "wp-velvet-2", "wp-velvet-3",
  ...[1, 2, 3, 4, 5, 6].map((n) => `wp-glass-${n}`),
  "wp-landscape-1", "wp-landscape-3", "wp-landscape-5", "wp-landscape-1-noir", "wp-landscape-3-noir",
]);

/** A light picture takes dark words over it. */
export const isLightWallpaper = (name: string): boolean => LIGHT.has(name) || name.endsWith("-clair");

function exists(name: string): boolean {
  const m = /^wp-([a-z]+)-([1-6])(?:-(noir|clair))?$/.exec(name);
  if (!m) return false;
  const theme = wallpaperThemes().find((x) => x.key === m[1]);
  return !!theme && (!m[3] || theme.tones);
}

/** The picked wallpaper (this PC only, like the Mac's browse defaults); a stale name falls back to Lava 3. */
export function currentWallpaper(): string {
  try {
    const v = localStorage.getItem(KEY);
    if (v && exists(v)) return v;
  } catch {
    // Storage refused: the default.
  }
  return DEFAULT_WALLPAPER;
}

export function setWallpaper(name: string): void {
  try {
    localStorage.setItem(KEY, name);
  } catch {
    // Not kept: the hero still shows it until the next start.
  }
}

export const wallpaperUrl = (name: string, thumb = false): string => `assets/wallpapers/${name}${thumb ? "-thumb" : ""}.jpg`;

// ---- category colours -----------------------------------------------------------------------

const CATEGORY_COLORS: Record<string, string> = {
  login: "#0E9F9F", password: "#0F5E63", email: "#BE185D", server: "#5B6472", database: "#5B6472",
  router: "#0F766E", apiCredential: "#0891B2", sshKey: "#475569", creditCard: "#2F80ED", bankAccount: "#E08A00",
  cryptoWallet: "#2563EB", subscription: "#9333EA", identity: "#22A06B", idCard: "#15803D", passport: "#1D4ED8",
  driverLicense: "#E11D48", socialSecurityNumber: "#1E40AF", medicalRecord: "#DC2626", membership: "#7C3AED",
  rewardProgram: "#DB2777", insurance: "#0D9488", vehicle: "#475569", accessCode: "#4338CA", secureNote: "#D99A1E",
  document: "#3478F6", softwareLicense: "#2563EB",
};

export const ACCENT = "#5856D6";
export const categoryColor = (key: string): string => CATEGORY_COLORS[key] ?? ACCENT;

// ---- identity colour ------------------------------------------------------------------------

type RGB = [number, number, number];

const hex = (c: string): RGB => {
  const n = parseInt(c.replace("#", ""), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
};
const css = ([r, g, b]: RGB, a = 1): string => `rgba(${Math.round(r)}, ${Math.round(g)}, ${Math.round(b)}, ${a.toFixed(3)})`;

/** The accent for a colour too gray to tint a wash (saturation under 0.15). */
function fallback(c: RGB): RGB {
  const high = Math.max(...c);
  const low = Math.min(...c);
  return (high > 0 ? (high - low) / high : 0) < 0.15 ? hex(ACCENT) : c;
}

/**
 * The dominant saturated colour of an icon: a 16 x 16 copy, pixels with alpha above 0.5, near
 * gray, black and white ones dropped, the rest in 12 hue buckets of 30 degrees centred on 0, 30...
 * and the mean of the fullest. Null when no pixel qualifies.
 */
export async function dominant(src: string): Promise<RGB | null> {
  const img = new Image();
  img.src = src;
  try {
    await img.decode();
  } catch {
    return null;
  }
  const side = 16;
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = side;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) return null;
  ctx.drawImage(img, 0, 0, side, side);
  const px = ctx.getImageData(0, 0, side, side).data;
  const sums = Array.from({ length: 12 }, () => [0, 0, 0, 0]);
  for (let i = 0; i < px.length; i += 4) {
    if (px[i + 3]! / 255 <= 0.5) continue;
    const r = px[i]! / 255, g = px[i + 1]! / 255, b = px[i + 2]! / 255;
    const high = Math.max(r, g, b);
    const chroma = high - Math.min(r, g, b);
    if (high < 0.2 || chroma / high < 0.25) continue;
    let hue = high === r ? (g - b) / chroma : high === g ? 2 + (b - r) / chroma : 4 + (r - g) / chroma;
    hue = (hue * 60) % 360;
    if (hue < 0) hue += 360;
    const s = sums[Math.floor((hue + 15) / 30) % 12]!;
    s[0]! += r; s[1]! += g; s[2]! += b; s[3]! += 1;
  }
  let best = 0;
  for (let i = 1; i < 12; i++) if (sums[i]![3]! > sums[best]![3]!) best = i;
  const w = sums[best]!;
  if (!w[3]) return null;
  return [(w[0]! / w[3]!) * 255, (w[1]! / w[3]!) * 255, (w[2]! / w[3]!) * 255];
}

/** The item's colour: its site icon's dominant colour (a colourless logo takes the accent), else its category's. */
export async function identityColor(itemType: string, iconSrc: string | null): Promise<RGB> {
  if (!iconSrc) return fallback(hex(categoryColor(itemType)));
  return (await dominant(iconSrc)) ?? hex(ACCENT);
}

export const categoryIdentity = (itemType: string): RGB => fallback(hex(categoryColor(itemType)));

/** `c` turned `degrees` around the HSB hue wheel, saturation and brightness kept. */
function rotated(c: RGB, degrees: number): RGB {
  const [r, g, b] = c.map((x) => x / 255) as RGB;
  const high = Math.max(r, g, b);
  const low = Math.min(r, g, b);
  const chroma = high - low;
  if (!chroma) return c;
  let hue = high === r ? (g - b) / chroma : high === g ? 2 + (b - r) / chroma : 4 + (r - g) / chroma;
  hue = (((hue * 60 + degrees) % 360) + 360) % 360;
  const s = chroma / high;
  const f = (n: number) => {
    const k = (n + hue / 60) % 6;
    return high - high * s * Math.max(0, Math.min(k, 4 - k, 1));
  };
  return [f(5) * 255, f(3) * 255, f(1) * 255];
}

/**
 * The two glows behind an item's header (Theme.Wash.identityGlows): ellipses from the top corners
 * reaching 71% of the box, the colour turned -14 and +22 degrees, peaks 0.14 (light) or 0.28
 * (dark), the trailing one at 85%, fading on a smoothstep curve. As a CSS background.
 */
export function identityWash(c: RGB, dark: boolean): string {
  const peak = dark ? 0.28 : 0.14;
  const glow = (col: RGB, p: number, at: string) =>
    `radial-gradient(ellipse 71% 71% at ${at}, ${css(col, p)} 0%, ${css(col, 0.844 * p)} 25%, ${css(col, 0.5 * p)} 50%, ${css(col, 0.156 * p)} 75%, ${css(col, 0)} 100%)`;
  // The leading glow is drawn over the trailing one: first in the CSS list.
  return [glow(rotated(c, -14), peak, "0% 0%"), glow(rotated(c, 22), peak * 0.85, "100% 0%")].join(", ");
}
