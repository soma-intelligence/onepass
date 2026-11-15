import Testing

extension Tag {
    /// Waits on the main actor, the main run loop, a local network round or wall-clock budgets,
    /// and timed out (or missed a budget) while the whole suite ran in parallel on a loaded Mac.
    /// scripts/verify.sh runs the tests carrying it on their own, one at a time, after the
    /// parallel run of all the others; a plain `swift test` still runs them with the rest.
    @Tag static var slow: Self
}
