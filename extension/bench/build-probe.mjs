// Builds dist-bench/probe.js, the probe core/onepass-bench injects into each page.
// Same defines as a heuristic production build (build.mjs): the bench measures what ships.
import { build } from "esbuild";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
await build({
  entryPoints: [join(root, "bench/entry.ts")],
  outfile: join(root, "dist-bench/probe.js"),
  bundle: true,
  format: "iife",
  target: "es2022",
  minify: false,
  logLevel: "warning",
  define: { __LAB_RECORDER__: "false", __CLASSIFIER__: JSON.stringify("heuristic"), __DEV__: "false", __ONEPASS_NATIVE_HOST__: JSON.stringify("me.somalabs.onepass") },
});
console.log(join(root, "dist-bench/probe.js"));
