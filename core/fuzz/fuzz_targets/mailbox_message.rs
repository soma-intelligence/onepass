#![no_main]

//! Every mailbox message type decoded from hostile bytes: no panic, and
//! whatever decodes re-encodes to exactly the input (strict codec).

use libfuzzer_sys::fuzz_target;
use onepass_mailbox_proto::*;

fn run<M: Message>(data: &[u8]) {
    if let Ok(m) = decode::<M>(data) {
        assert_eq!(encode(&m), data);
    }
}

fuzz_target!(|data: &[u8]| {
    run::<Body>(data);
    run::<ServerRecord>(data);
    run::<ChangesPage>(data);
    run::<Op>(data);
    run::<CommitOp>(data);
    run::<CommitRequest>(data);
    run::<CommitResponse>(data);
    run::<ConflictEntry>(data);
    run::<CreateMailbox>(data);
    run::<MailboxCreated>(data);
    run::<Limits>(data);
    run::<Usage>(data);
    run::<MailboxInfo>(data);
    run::<ServerConfig>(data);
    run::<SetPush>(data);
    run::<BlobAnnounce>(data);
    run::<BlobUrls>(data);
    run::<BlobLookup>(data);
    run::<ErrorBody>(data);
    run::<CredentialRole>(data);
    run::<GrantCredential>(data);
    run::<SetCredentialRole>(data);
    run::<SetLocator>(data);
    run::<Located>(data);
});
