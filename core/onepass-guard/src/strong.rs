//! Strong authentication (spec 4.4): proof that the device owner is present,
//! on top of the prompt with a confirmation code. The prompt says what is
//! approved, strong authentication proves who approves it.
//!
//! - [`LocalAuthStrong`]: LocalAuthentication on macOS (Touch ID, Apple
//!   Watch, or the macOS session password), `Unavailable` elsewhere.
//! - [`FallbackStrong`]: a check provided by the caller (the CLI retypes the
//!   master password on `/dev/tty`).
//! - [`ChainStrong`]: tries each in turn; never allows when none is usable.
//! - [`DevStrong`]: `ONEPASS_DEV_STRONG_AUTH=allow|deny`, debug builds only.

use std::time::Duration;

/// Result of a strong authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrongOutcome {
    /// The device owner authenticated.
    Verified,
    /// Authentication failed, was cancelled or timed out.
    Denied,
    /// This method cannot run here (no hardware, no user interface, not
    /// configured): the next method may be tried.
    Unavailable,
}

/// A strong authentication method.
pub trait StrongAuth: Send + Sync {
    /// Asks the device owner to authenticate. `reason` is shown to the user
    /// (it names the client and the target) and must not hold a secret.
    fn verify(&self, reason: &str) -> StrongOutcome;
}

/// How long LocalAuthentication may take before the request is denied.
pub const LOCAL_AUTH_TIMEOUT: Duration = Duration::from_secs(60);

/// LocalAuthentication with the policy "device owner authentication" (Touch
/// ID, Apple Watch, or the session password as the system's own fallback).
/// `Unavailable` when the policy cannot be evaluated (no biometry and no
/// password set, no user interface, SSH session) and on other systems.
#[derive(Clone, Copy, Debug)]
pub struct LocalAuthStrong {
    /// How long to wait for the system's answer before denying.
    pub timeout: Duration,
}

impl LocalAuthStrong {
    /// With the default 60 s timeout.
    pub fn new() -> Self {
        LocalAuthStrong {
            timeout: LOCAL_AUTH_TIMEOUT,
        }
    }
}

impl Default for LocalAuthStrong {
    fn default() -> Self {
        Self::new()
    }
}

impl StrongAuth for LocalAuthStrong {
    fn verify(&self, reason: &str) -> StrongOutcome {
        #[cfg(target_os = "macos")]
        {
            crate::strong_macos::evaluate(reason, self.timeout)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = reason;
            StrongOutcome::Unavailable
        }
    }
}

/// Strong authentication by a check the caller provides, typically the
/// master password retyped on `/dev/tty` and verified against the account.
/// The check returns true only when the user proved who they are.
pub struct FallbackStrong<P: Fn(&str) -> bool + Send + Sync> {
    check: P,
}

impl<P: Fn(&str) -> bool + Send + Sync> FallbackStrong<P> {
    /// Wraps `check`, called with the reason.
    pub fn new(check: P) -> Self {
        FallbackStrong { check }
    }
}

impl<P: Fn(&str) -> bool + Send + Sync> StrongAuth for FallbackStrong<P> {
    fn verify(&self, reason: &str) -> StrongOutcome {
        if (self.check)(reason) {
            StrongOutcome::Verified
        } else {
            StrongOutcome::Denied
        }
    }
}

/// Tries each method in order: the first `Verified` or `Denied` is the
/// answer, `Unavailable` moves on to the next. When none is available (or
/// the chain is empty) the answer is `Denied`: strong authentication never
/// allows by default.
pub struct ChainStrong(pub Vec<Box<dyn StrongAuth>>);

impl StrongAuth for ChainStrong {
    fn verify(&self, reason: &str) -> StrongOutcome {
        for method in &self.0 {
            match method.verify(reason) {
                StrongOutcome::Unavailable => continue,
                decided => return decided,
            }
        }
        StrongOutcome::Denied
    }
}

/// Fixed answer for end-to-end tests (debug builds only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DevStrong {
    /// True for `allow`, false for `deny`. Private: built only by
    /// [`dev_strong_from_env`] (and `testing::dev_strong` in tests).
    allow: bool,
}

impl StrongAuth for DevStrong {
    fn verify(&self, _reason: &str) -> StrongOutcome {
        if self.allow {
            StrongOutcome::Verified
        } else {
            StrongOutcome::Denied
        }
    }
}

/// Pure parser behind [`dev_strong_from_env`].
pub(crate) fn parse_dev_strong(
    value: Option<&str>,
    debug: bool,
) -> Result<Option<DevStrong>, String> {
    let Some(v) = value else {
        return Ok(None);
    };
    if !debug {
        return Err("ONEPASS_DEV_STRONG_AUTH is only accepted in debug builds".into());
    }
    match v {
        "allow" => Ok(Some(DevStrong { allow: true })),
        "deny" => Ok(Some(DevStrong { allow: false })),
        _ => Err("ONEPASS_DEV_STRONG_AUTH must be allow or deny".into()),
    }
}

/// Reads `ONEPASS_DEV_STRONG_AUTH`: `None` when unset, `Err` on an unknown
/// value or in a release build.
pub fn dev_strong_from_env() -> Result<Option<DevStrong>, String> {
    let value = std::env::var("ONEPASS_DEV_STRONG_AUTH").ok();
    parse_dev_strong(value.as_deref(), cfg!(debug_assertions))
}

/// Test helpers.
pub mod testing {
    use super::DevStrong;

    /// A fixed strong-authentication answer, for tests of other crates.
    pub fn dev_strong(allow: bool) -> DevStrong {
        DevStrong { allow }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixed(StrongOutcome, AtomicUsize);

    impl Fixed {
        fn boxed(o: StrongOutcome) -> Box<dyn StrongAuth> {
            Box::new(Fixed(o, AtomicUsize::new(0)))
        }
    }

    impl StrongAuth for Fixed {
        fn verify(&self, _reason: &str) -> StrongOutcome {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0
        }
    }

    #[test]
    fn strong_auth_unavailable_falls_back_never_allows() {
        use StrongOutcome::*;
        let chain = |v: Vec<StrongOutcome>| ChainStrong(v.into_iter().map(Fixed::boxed).collect());
        assert_eq!(chain(vec![Unavailable, Denied]).verify("r"), Denied);
        assert_eq!(chain(vec![Unavailable, Verified]).verify("r"), Verified);
        assert_eq!(chain(vec![Unavailable, Unavailable]).verify("r"), Denied);
        assert_eq!(chain(vec![]).verify("r"), Denied);
        // A refusal by the first method is final: no fallback after Denied.
        assert_eq!(chain(vec![Denied, Verified]).verify("r"), Denied);
        assert_eq!(chain(vec![Verified, Denied]).verify("r"), Verified);
    }

    #[test]
    fn chain_stops_at_the_first_answer() {
        let second = std::sync::Arc::new(AtomicUsize::new(0));
        struct Count(std::sync::Arc<AtomicUsize>);
        impl StrongAuth for Count {
            fn verify(&self, _: &str) -> StrongOutcome {
                self.0.fetch_add(1, Ordering::SeqCst);
                StrongOutcome::Verified
            }
        }
        let chain = ChainStrong(vec![
            Fixed::boxed(StrongOutcome::Denied),
            Box::new(Count(second.clone())),
        ]);
        assert_eq!(chain.verify("r"), StrongOutcome::Denied);
        assert_eq!(second.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fallback_maps_the_check_and_sees_the_reason() {
        let seen = Mutex::new(Vec::new());
        let f = FallbackStrong::new(|reason: &str| {
            seen.lock().unwrap().push(reason.to_owned());
            reason == "ok"
        });
        assert_eq!(f.verify("ok"), StrongOutcome::Verified);
        assert_eq!(f.verify("no"), StrongOutcome::Denied);
        assert_eq!(*seen.lock().unwrap(), ["ok", "no"]);
    }

    #[test]
    fn dev_strong_parses_values_in_debug_only() {
        assert_eq!(parse_dev_strong(None, true), Ok(None));
        assert_eq!(parse_dev_strong(None, false), Ok(None));
        let allow = parse_dev_strong(Some("allow"), true).unwrap().unwrap();
        let deny = parse_dev_strong(Some("deny"), true).unwrap().unwrap();
        assert_eq!(allow.verify("r"), StrongOutcome::Verified);
        assert_eq!(deny.verify("r"), StrongOutcome::Denied);
        assert!(parse_dev_strong(Some("yes"), true).is_err());
        assert!(parse_dev_strong(Some("allow"), false).is_err());
    }

    #[test]
    fn local_auth_strong_has_a_bounded_timeout() {
        assert_eq!(LocalAuthStrong::new().timeout, Duration::from_secs(60));
        // Usable as a trait object in a chain.
        let _chain = ChainStrong(vec![Box::new(LocalAuthStrong::new())]);
    }

    /// Manual: shows a real Touch ID / password sheet. Run with
    /// `cargo test -p onepass-guard -- --ignored touch_id_manual --nocapture`.
    #[test]
    #[ignore = "manual: needs a person at the Mac"]
    fn touch_id_manual() {
        let outcome = LocalAuthStrong::new().verify("test OnePass strong approval (manual test)");
        println!("\noutcome={outcome:?}");
    }
}
