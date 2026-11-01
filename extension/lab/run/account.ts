// How the lab names the account a driver looks for in the extension's UI.
// The generator gives a sign-in-with-a-provider site the title
// "<item title> via <Provider>" (gen/generate.ts), while the overlay shows the
// vault item's own title on the row and the provider on the row's
// `data-provider` ("Avec <Provider> · <email>" on its second line). The
// drivers match such a row on both: the item title and the provider.
import type { ProviderId } from "../gen/model.ts";

export interface AccountRow { title: string; provider?: ProviderId }

const VIA: Record<string, ProviderId> = { Google: "google", Apple: "apple", Microsoft: "microsoft" };

/** The row a site's account title stands for: "<brand> via <Provider>" is the brand's row for that provider. */
export function accountRow(itemTitle: string): AccountRow {
  const m = / via (Google|Apple|Microsoft)$/.exec(itemTitle);
  if (!m) return { title: itemTitle };
  return { title: itemTitle.slice(0, m.index), provider: VIA[m[1]!]! };
}

/** CSS selector of the overlay's account rows that can match `row` (the title is matched on `.t1`). */
export function overlayRowSelector(row: AccountRow): string {
  return row.provider ? `.ov-account:not(.ov-sub)[data-provider="${row.provider}"]` : ".ov-account:not(.ov-sub)";
}
