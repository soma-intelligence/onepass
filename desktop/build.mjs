// Bundles the UI into dist/: one script, one stylesheet, one page. No
// remote resource, no inline script or style (the CSP refuses them).
import { build } from "esbuild";
import { cpSync, mkdirSync, rmSync } from "node:fs";

rmSync("dist", { recursive: true, force: true });
mkdirSync("dist", { recursive: true });

await build({
  entryPoints: ["src/main.ts"],
  bundle: true,
  format: "esm",
  target: "es2022",
  outfile: "dist/main.js",
  minify: true,
  sourcemap: false,
  legalComments: "none",
});

cpSync("src/index.html", "dist/index.html");
cpSync("src/styles.css", "dist/styles.css");
console.log("built dist/");
