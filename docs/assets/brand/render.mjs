// Renders every OnePass icon from the Lattice mark below: the iOS, Mac, Watch
// and visionOS app icons, the extension icons and the master SVGs.
//
//   cd extension && npm ci && node ../docs/assets/brand/render.mjs
//
// Playwright is taken from the extension's node_modules (cwd). Set CHROMIUM
// to a Chromium binary when Playwright's own browser is not installed.
import { createRequire } from "node:module";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(join(process.cwd(), "/"));
const { chromium } = require("@playwright/test");

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "../../..");

// The mark on a 100 x 100 grid: a 2 x 3 lattice of dots and one bar where the
// third column would be. Dots are the many keys, the bar is the one pass.
const DOTS = [23.5, 49.5].flatMap((cx) => [24, 50, 76].map((cy) => [cx, cy]));
const DOT_R = 9;
const DOT_OPACITY = 0.55;
const BAR = { x: 67.5, y: 15, w: 18, h: 70 };

const dots = (color) =>
  DOTS.map(([cx, cy]) => `<circle cx="${cx}" cy="${cy}" r="${DOT_R}" fill="${color}" fill-opacity="${DOT_OPACITY}"/>`).join("");
const bar = (color) => `<rect x="${BAR.x}" y="${BAR.y}" width="${BAR.w}" height="${BAR.h}" rx="${BAR.w / 2}" fill="${color}"/>`;
const svg = (body, box = "0 0 100 100") => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${box}">${body}</svg>`;

const ACCENT = "#5856D6";
const GRADIENT = `<linearGradient id="g" x1="0.33" y1="0" x2="0.67" y2="1"><stop offset="0" stop-color="#6E6CF0"/><stop offset="0.45" stop-color="${ACCENT}"/><stop offset="1" stop-color="#3F3DB8"/></linearGradient>`;

/** A 1024 canvas: optional tile (inset, radius), mark centred at `scale` of 1024. */
function canvas({ tile = null, layers = "both", scale = 0.56, background = true, shadow = false }) {
  const m = 1024 * scale;
  const o = (1024 - m) / 2;
  const tileRect = tile
    ? `<rect x="${tile.inset}" y="${tile.inset}" width="${1024 - 2 * tile.inset}" height="${1024 - 2 * tile.inset}" rx="${tile.radius}" fill="url(#g)"${shadow ? ' filter="url(#s)"' : ""}/>`
    : background
      ? `<rect width="1024" height="1024" fill="url(#g)"/>`
      : "";
  const body =
    layers === "none" ? "" : layers === "dots" ? dots("#FFFFFF") : layers === "bar" ? bar("#FFFFFF") : dots("#FFFFFF") + bar("#FFFFFF");
  return svg(
    `<defs>${GRADIENT}<filter id="s" x="-10%" y="-10%" width="120%" height="125%"><feDropShadow dx="0" dy="12" stdDeviation="14" flood-color="#1B1A4A" flood-opacity="0.3"/></filter></defs>` +
      tileRect +
      `<svg x="${o}" y="${o}" width="${m}" height="${m}" viewBox="0 0 100 100">${body}</svg>`,
    "0 0 1024 1024",
  );
}

const APPLE = join(repo, "apple");
const APPICON = join(APPLE, "App/Resources/Assets.xcassets/AppIcon.appiconset");
const STACK = join(APPLE, "App/Resources/Assets.xcassets/AppIcon.solidimagestack");
const MAC_TILE = { inset: 100, radius: 185 };

/** [file, svg, pixel size, opaque] */
const jobs = [
  [join(APPICON, "AppIcon-ios.png"), canvas({}), 1024, true],
  [join(APPLE, "Watch/Assets.xcassets/AppIcon.appiconset/AppIcon-watch.png"), canvas({ scale: 0.52 }), 1024, true],
  [join(STACK, "Back.solidimagestacklayer/Content.imageset/Back.png"), canvas({ layers: "none" }), 1024, true],
  [join(STACK, "Middle.solidimagestacklayer/Content.imageset/Middle.png"), canvas({ layers: "dots", background: false }), 1024, false],
  [join(STACK, "Front.solidimagestacklayer/Content.imageset/Front.png"), canvas({ layers: "bar", background: false }), 1024, false],
];
for (const pt of [16, 32, 128, 256, 512]) {
  for (const scale of [1, 2]) {
    const name = `AppIcon-mac-${pt}${scale === 2 ? "@2x" : ""}.png`;
    jobs.push([join(APPICON, name), canvas({ tile: MAC_TILE, shadow: true, scale: 0.46 }), pt * scale, false]);
  }
}
for (const px of [16, 32, 48, 128]) {
  jobs.push([
    join(repo, `extension/src/icons/icon-${px}.png`),
    canvas({ tile: { inset: 0, radius: 225 }, scale: 0.64 }),
    px,
    false,
  ]);
}

const browser = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
for (const [file, art, px, opaque] of jobs) {
  const page = await browser.newPage({ viewport: { width: 1024, height: 1024 }, deviceScaleFactor: px / 1024 });
  await page.setContent(`<html><body style="margin:0;background:transparent">${art.replace("<svg ", '<svg width="1024" height="1024" ')}</body></html>`);
  mkdirSync(dirname(file), { recursive: true });
  await page.screenshot({ path: file, omitBackground: !opaque, clip: { x: 0, y: 0, width: 1024, height: 1024 } });
  await page.close();
}
await browser.close();

writeFileSync(join(here, "mark.svg"), svg(dots(ACCENT) + bar(ACCENT)) + "\n");
writeFileSync(join(here, "mark-white.svg"), svg(dots("#FFFFFF") + bar("#FFFFFF")) + "\n");
writeFileSync(join(here, "icon.svg"), canvas({}) + "\n");
console.log(`${jobs.length} PNGs and 3 SVGs written`);
