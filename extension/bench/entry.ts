// Entry of dist-bench/probe.js: installs the submit guard at once, then exposes the probe.
import { createProbe, installGuard, prune } from "./probe";

installGuard(window);
(globalThis as { __onepassBench?: unknown }).__onepassBench = { createProbe, installGuard, prune };
