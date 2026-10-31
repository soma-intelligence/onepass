// Dev-only popup button: downloads every recorded step as JSON.
import { ext } from "../shared/browser";
import { MSG_EXPORT } from "./recorder";

export function mountExportButton(doc: Document): void {
  const b = doc.createElement("button");
  b.textContent = "Export recorded steps (dev)";
  b.style.cssText = "display:block;margin:8px auto;font:12px sans-serif";
  b.addEventListener("click", () => {
    void (ext.runtime.sendMessage({ type: MSG_EXPORT }) as Promise<{ ok?: { steps?: unknown } } | undefined>).then((r) => {
      const steps = r?.ok?.steps;
      if (!Array.isArray(steps)) return;
      const url = URL.createObjectURL(new Blob([JSON.stringify({ version: 1, steps }, null, 2)], { type: "application/json" }));
      const a = doc.createElement("a");
      a.href = url;
      a.download = "onepass-recorded-steps.json";
      a.click();
      URL.revokeObjectURL(url);
    });
  });
  doc.body.appendChild(b);
}

export default mountExportButton;
