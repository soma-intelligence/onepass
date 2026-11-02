//! Hedged randomness: the one source of fresh random bytes in the core.
//!
//! Every byte the core draws for a secret (account keys, the Secret Key,
//! vault, item and attachment keys, device keys, pairing secrets, recovery
//! material, passkeys) and every nonce comes from `fill_random`. It does not
//! hand out the operating system CSPRNG directly: each call runs
//!
//! ```text
//! PRK = HMAC-SHA-512(key = "onepass/rng/v1",
//!                    os (64) || device_seed (32) || counter (8, BE) || instance (16))
//! OKM = HKDF-Expand-SHA-512(PRK, info = "onepass/rng/v1", L)
//! ```
//!
//! (HKDF-SHA-512, RFC 5869, with the label as salt), where `os` is 64 fresh
//! bytes from the OS CSPRNG (through aws-lc), `device_seed` is a 32-byte
//! secret made once per install and kept in the platform keychain
//! (`set_device_seed`), `counter` is a process-wide monotonic counter and
//! `instance` is the wall clock at first use and the process id. Requests
//! longer than one HKDF output (16320 bytes) run one extraction per block.
//!
//! What it buys: a broken or backdoored OS generator alone does not make keys
//! predictable while the device seed stays secret, and a leaked device seed
//! alone gives nothing while the OS generator works. `counter` and `instance`
//! carry no entropy: they only keep two outputs from ever repeating, in one
//! process and across restarts, even if the OS generator repeated itself.
//!
//! Without a device seed (the CLI, tests, the apps before setup) the seed
//! field is 32 zero bytes and the output is exactly as strong as the OS
//! generator, no weaker. See `docs/security.md`, section "Randomness".

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::hmac;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Domain label: HKDF salt and info.
const LABEL: &[u8] = b"onepass/rng/v1";
/// Fresh OS bytes per extraction.
const OS_LEN: usize = 64;
/// Length of the per-install device seed.
pub const DEVICE_SEED_LEN: usize = 32;
const HASH_LEN: usize = 64;
/// RFC 5869: at most 255 blocks per expansion.
const MAX_EXPAND: usize = 255 * HASH_LEN;
const IKM_LEN: usize = OS_LEN + DEVICE_SEED_LEN + 8 + 16;

static DEVICE_SEED: RwLock<Option<Zeroizing<[u8; DEVICE_SEED_LEN]>>> = RwLock::new(None);
static COUNTER: AtomicU64 = AtomicU64::new(0);
static INSTANCE: OnceLock<[u8; 16]> = OnceLock::new();

/// Install this device's seed (32 bytes from the keychain). Replaces any
/// previous one. An all-zero or wrongly sized seed is refused.
pub fn set_device_seed(seed: &[u8]) -> Result<()> {
    if seed.len() != DEVICE_SEED_LEN {
        return Err(Error::InvalidFormat("device seed length"));
    }
    // Branch only on "all zero", never on where a byte differs.
    if seed.iter().fold(0u8, |acc, b| acc | b) == 0 {
        return Err(Error::InvalidFormat("device seed"));
    }
    let mut s = Zeroizing::new([0u8; DEVICE_SEED_LEN]);
    s.copy_from_slice(seed);
    *DEVICE_SEED.write().map_err(|_| Error::Crypto)? = Some(s);
    Ok(())
}

/// Whether a device seed is installed (otherwise the output is OS random only).
pub fn has_device_seed() -> bool {
    DEVICE_SEED.read().map(|s| s.is_some()).unwrap_or(false)
}

/// A new device seed, to store in the keychain then pass to `set_device_seed`.
/// Made once per install: from the OS generator (hedged by any seed already
/// installed, none on first use).
pub fn new_device_seed() -> Result<Zeroizing<[u8; DEVICE_SEED_LEN]>> {
    let mut s = Zeroizing::new([0u8; DEVICE_SEED_LEN]);
    fill_random(&mut *s)?;
    Ok(s)
}

/// Fill `buf` with hedged random bytes (see the module documentation).
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    let instance = INSTANCE.get_or_init(instance_tag);
    let seed = {
        let guard = DEVICE_SEED.read().map_err(|_| Error::Crypto)?;
        let mut s = Zeroizing::new([0u8; DEVICE_SEED_LEN]);
        if let Some(seed) = guard.as_ref() {
            s.copy_from_slice(&**seed);
        }
        s
    };
    for chunk in buf.chunks_mut(MAX_EXPAND) {
        let mut os = Zeroizing::new([0u8; OS_LEN]);
        aws_lc_rs::rand::fill(&mut *os).map_err(|_| Error::Crypto)?;
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        hedge(&os, &seed, counter, instance, chunk);
    }
    Ok(())
}

/// Return `N` hedged random bytes.
///
/// The returned array is a plain copy that is not wiped. For secret material,
/// use `fill_random` into a zeroizing buffer instead.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill_random(&mut out)?;
    Ok(out)
}

/// The construction itself, deterministic in its inputs (known-answer tested).
/// `out` is at most `MAX_EXPAND` bytes.
fn hedge(
    os: &[u8; OS_LEN],
    seed: &[u8; DEVICE_SEED_LEN],
    counter: u64,
    instance: &[u8; 16],
    out: &mut [u8],
) {
    debug_assert!(out.len() <= MAX_EXPAND);
    let mut ikm = Zeroizing::new([0u8; IKM_LEN]);
    ikm[..OS_LEN].copy_from_slice(os);
    ikm[OS_LEN..OS_LEN + DEVICE_SEED_LEN].copy_from_slice(seed);
    ikm[OS_LEN + DEVICE_SEED_LEN..OS_LEN + DEVICE_SEED_LEN + 8]
        .copy_from_slice(&counter.to_be_bytes());
    ikm[OS_LEN + DEVICE_SEED_LEN + 8..].copy_from_slice(instance);

    // HKDF-Extract(salt = LABEL, IKM).
    let salt = hmac::Key::new(hmac::HMAC_SHA512, LABEL);
    let prk = Zeroizing::new(hmac::sign(&salt, &*ikm).as_ref().to_vec());
    // HKDF-Expand(PRK, info = LABEL, L).
    let prk_key = hmac::Key::new(hmac::HMAC_SHA512, &prk);
    let mut t = Zeroizing::new(Vec::<u8>::new());
    for (i, block) in out.chunks_mut(HASH_LEN).enumerate() {
        let mut ctx = hmac::Context::with_key(&prk_key);
        ctx.update(&t);
        ctx.update(LABEL);
        // i < 255 by MAX_EXPAND.
        ctx.update(&[(i + 1) as u8]);
        *t = ctx.sign().as_ref().to_vec();
        block.copy_from_slice(&t[..block.len()]);
    }
}

/// Wall clock at first use (nanoseconds) and process id: not a secret, not
/// entropy, only a tag that differs between two runs of the process.
fn instance_tag() -> [u8; 16] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut tag = [0u8; 16];
    tag[..8].copy_from_slice(&nanos.to_be_bytes());
    tag[8..12].copy_from_slice(&std::process::id().to_be_bytes());
    tag
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn arrays_differ_and_are_not_zero() {
        let a = random_array::<32>().unwrap();
        let b = random_array::<32>().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn fill_handles_empty_buffer() {
        fill_random(&mut []).unwrap();
    }

    /// Known answer, computed independently with Python's `hmac` module:
    /// os = 00..3f, seed = 40..5f, counter = 7, instance = 60..6f, L = 80.
    #[test]
    fn hedge_known_answer() {
        let os: [u8; 64] = core::array::from_fn(|i| i as u8);
        let seed: [u8; 32] = core::array::from_fn(|i| 0x40 + i as u8);
        let inst: [u8; 16] = core::array::from_fn(|i| 0x60 + i as u8);
        let mut out = [0u8; 80];
        hedge(&os, &seed, 7, &inst, &mut out);
        assert_eq!(hex(&out), KAT_80);
        // A prefix of a longer output: HKDF-Expand blocks.
        let mut short = [0u8; 16];
        hedge(&os, &seed, 7, &inst, &mut short);
        assert_eq!(short, out[..16]);
    }

    const KAT_80: &str = "7d48354c8cfa9e1cd18380438a19f4d3669e51b4b970ef9213b5909de96d04bb\
         c59395a8a12211b8c1d8727f030f19cdcac5ce3bebb559bb86db303856c55481\
         fb1e524cd2e44c466f5890071ebff6e8";

    /// A dead OS generator (always the same bytes): the counter still keeps
    /// outputs apart, and without the seed nobody can recompute them.
    #[test]
    fn constant_os_output_never_repeats_and_depends_on_seed() {
        let os = [0u8; 64];
        let inst = [9u8; 16];
        let mut seen = HashSet::new();
        for c in 0..1000u64 {
            let mut o = [0u8; 32];
            hedge(&os, &[1u8; 32], c, &inst, &mut o);
            assert!(seen.insert(o));
        }
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        hedge(&os, &[1u8; 32], 0, &inst, &mut a);
        hedge(&os, &[2u8; 32], 0, &inst, &mut b);
        assert_ne!(a, b);
        // Another process (instance) with the same counter: different output.
        hedge(&os, &[1u8; 32], 0, &[8u8; 16], &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn calls_never_repeat() {
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(random_array::<16>().unwrap()));
        }
    }

    #[test]
    fn long_buffers_have_no_repeated_blocks() {
        let mut big = vec![0u8; 2 * MAX_EXPAND + 100];
        fill_random(&mut big).unwrap();
        let blocks: HashSet<&[u8]> = big.chunks(HASH_LEN).collect();
        assert_eq!(blocks.len(), big.len().div_ceil(HASH_LEN));
    }

    #[test]
    fn device_seed_is_validated_and_used() {
        assert!(set_device_seed(&[0u8; 32]).is_err());
        assert!(set_device_seed(&[1u8; 31]).is_err());
        let seed = new_device_seed().unwrap();
        set_device_seed(&*seed).unwrap();
        assert!(has_device_seed());
        assert_ne!(random_array::<32>().unwrap(), random_array::<32>().unwrap());
    }
}
