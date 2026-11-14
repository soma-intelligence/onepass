#![no_main]

//! Sealed org keysets as a hostile org mailbox serves them: decoding must
//! not panic, and whatever decodes re-encodes to the same bytes.

use libfuzzer_sys::fuzz_target;
use onepass_core::org::SealedOrgKeyset;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = SealedOrgKeyset::decode(data) {
        assert_eq!(s.encode(), data);
    }
});
