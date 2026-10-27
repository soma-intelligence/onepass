//! LocalAuthentication (Touch ID, Apple Watch, session password) on macOS.
//!
//! The only module of this crate that calls Objective-C; every `unsafe`
//! block carries its SAFETY argument.
#![allow(unsafe_code)]

use crate::display::sanitize_for_display;
use crate::strong::StrongOutcome;
use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAError, LAErrorDomain, LAPolicy};
use std::sync::mpsc;
use std::time::Duration;

/// Reason shown when the caller gives an empty one (LocalAuthentication
/// raises an Objective-C exception on an empty reason).
const DEFAULT_REASON: &str = "approve a OnePass request";

/// LocalAuthentication error codes meaning "cannot run here" rather than
/// "the user failed or refused".
const UNAVAILABLE_CODES: [LAError; 4] = [
    LAError::PasscodeNotSet,
    LAError::BiometryNotAvailable,
    LAError::CompanionNotAvailable,
    LAError::NotInteractive,
];

/// Maps the reply of `evaluatePolicy`. `error` is `(in LAErrorDomain, code)`
/// when the reply carried an error.
pub(crate) fn classify(success: bool, error: Option<(bool, isize)>) -> StrongOutcome {
    match (success, error) {
        (true, None) => StrongOutcome::Verified,
        (_, Some((true, code))) if UNAVAILABLE_CODES.iter().any(|c| c.0 == code) => {
            StrongOutcome::Unavailable
        }
        _ => StrongOutcome::Denied,
    }
}

/// `(in LAErrorDomain, code)` of `e`.
fn error_info(e: &NSError) -> (bool, isize) {
    // SAFETY: `LAErrorDomain` is an immutable NSString constant exported by
    // the framework, valid for the life of the process.
    let domain = unsafe { LAErrorDomain };
    (e.domain().isEqualToString(domain), e.code())
}

/// Evaluates the policy "device owner authentication" with `reason`,
/// waiting at most `timeout` for the reply (then the evaluation is cancelled
/// and the answer is `Denied`).
pub(crate) fn evaluate(reason: &str, timeout: Duration) -> StrongOutcome {
    let reason = sanitize_for_display(reason);
    let reason = if reason.trim().is_empty() {
        DEFAULT_REASON.to_owned()
    } else {
        reason
    };
    let policy = LAPolicy::DeviceOwnerAuthentication;

    // SAFETY: `+[LAContext new]` has no precondition and returns an owned,
    // fully initialized context.
    let ctx = unsafe { LAContext::new() };
    // SAFETY: `ctx` is a valid context and `policy` one of the defined
    // LAPolicy values; the error out-parameter is handled by the binding.
    if let Err(e) = unsafe { ctx.canEvaluatePolicy_error(policy) } {
        // "Cannot run here" codes give Unavailable, anything else Denied.
        return classify(false, Some(error_info(&e)));
    }

    // The reply runs once on a private queue; a full or closed channel only
    // means nobody waits any more (timeout), which is fine to ignore.
    let (tx, rx) = mpsc::sync_channel::<StrongOutcome>(1);
    let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
        // SAFETY: LocalAuthentication passes either null or a valid NSError
        // that stays alive for the duration of this call; it is only read
        // here, never retained beyond it.
        let error = unsafe { error.as_ref() }.map(error_info);
        let _ = tx.try_send(classify(success.as_bool(), error));
    });
    let text = NSString::from_str(&reason);
    // SAFETY: `ctx`, `text` and `reply` are valid for the call; the context
    // copies the block (it lives until it has replied) and the block only
    // owns a `SyncSender`, which is `Send` and may run on any queue. `text`
    // is non-empty, so no Objective-C exception is raised.
    unsafe { ctx.evaluatePolicy_localizedReason_reply(policy, &text, &reply) };

    match rx.recv_timeout(timeout) {
        Ok(outcome) => outcome,
        Err(_) => {
            // SAFETY: `ctx` is valid; invalidating cancels the pending
            // evaluation (its reply then reports a cancellation nobody reads).
            unsafe { ctx.invalidate() };
            StrongOutcome::Denied
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_are_classified() {
        use StrongOutcome::*;
        assert_eq!(classify(true, None), Verified);
        assert_eq!(classify(false, None), Denied);
        // Unavailable only for the "cannot run here" codes of LAErrorDomain.
        for code in [-5, -6, -11, -1004] {
            assert_eq!(classify(false, Some((true, code))), Unavailable);
            assert_eq!(classify(false, Some((false, code))), Denied);
        }
        // Failed, cancelled, locked out, invalid context: denied.
        for code in [-1, -2, -3, -4, -8, -9, -10] {
            assert_eq!(classify(false, Some((true, code))), Denied);
        }
        // An error alongside a success is not trusted.
        assert_eq!(classify(true, Some((true, -1))), Denied);
    }
}
