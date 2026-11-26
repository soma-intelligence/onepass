# DesignBridge (vendored)

DesignBridgeKit and DesignBridgeTesting come from DesignBridge, the Soma Labs bridge between
Penpot and SwiftUI. They are copied here so the Kelid repository builds on its own.

- DesignBridgeKit: toast, rolling numbers, motion, states, glass and theme primitives used by
  DesignKit and the app (the RX look).
- DesignBridgeTesting: the snapshot matrix, the XCUITest base class and `dbdiff`.

Source: DesignBridge commit 087405a. Edit the upstream copy first, then copy it here again.
One local change: the number demo in `DBCatalogue.swift` steps through a fixed cycle instead of
`Int.random`, because `core/onepass-core/tests/rng_guard.rs` forbids OS random draws in `apple/`.

Same license as the rest of this repository (AGPL-3.0, see `LICENSE` at the root).
