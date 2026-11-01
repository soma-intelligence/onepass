//! The conformance suite against a real mailbox on a LOCAL Supabase stack
//! (`supabase start`, the functions served, `mailbox/scripts/local-env.sh`
//! and `mailbox/scripts/e2e-admin.sh setup` run), plus what only a real
//! stack can show: Storage's answer to a second upload of the same object,
//! `no_route` against `not_found`, and a commit waking a `WakeListener`
//! through the stack's own Realtime.
//!
//!   ONEPASS_MAILBOX_E2E_URL     base URL of the function, for example
//!                               http://127.0.0.1:57421/functions/v1/mailbox
//!   ONEPASS_MAILBOX_E2E_INVITE  invite of a small plan (e2e-admin.sh setup)
//!   ONEPASS_MAILBOX_E2E_ADMIN   path of mailbox/scripts/e2e-admin.sh
//!                               (default: found from this crate)
//!
//! Without ONEPASS_MAILBOX_E2E_URL the test prints why and passes. The CI
//! workflow .github/workflows/mailbox.yml sets all three.

use std::path::PathBuf;
use std::process::Command;

use onepass_mailbox::testing::{ConformanceTarget, run_conformance};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use onepass_mailbox::{
    Credential, Endpoint, ErrorCode, MailboxApi, MailboxClient, MailboxError, RdvRole, Rendezvous,
    WakeListener,
};
use onepass_mailbox_proto::{Body, CommitOp, Op};
use onepass_mailbox_proto::{MailboxId, blob_sha256, hex};

struct E2e {
    endpoint: Endpoint,
    invite: Option<Vec<u8>>,
    admin: PathBuf,
}

impl E2e {
    fn admin(&self, args: &[&str]) {
        let out = Command::new(&self.admin)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("{}: {e}", self.admin.display()));
        assert!(
            out.status.success(),
            "e2e-admin.sh {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn mailbox_client(&self) -> MailboxClient {
        MailboxClient::new(self.endpoint.clone(), Credential::generate().unwrap()).unwrap()
    }
}

impl ConformanceTarget for E2e {
    fn client(&mut self) -> Box<dyn MailboxApi> {
        Box::new(self.mailbox_client())
    }

    fn invite(&self) -> Option<Vec<u8>> {
        self.invite.clone()
    }

    fn purge_tombstones(&mut self, mailbox: MailboxId) {
        self.admin(&["purge", &hex(&mailbox)]);
    }

    fn rendezvous(&mut self, session: [u8; 16], role: RdvRole) -> Rendezvous {
        Rendezvous::new(self.endpoint.clone(), session, role).expect("rendezvous")
    }

    fn locate(&mut self, locator: [u8; 16]) -> Result<Vec<MailboxId>, MailboxError> {
        onepass_mailbox::locate(&self.endpoint, locator)
    }

    fn before_case(&mut self) {
        self.admin(&["reset-rate"]);
    }
}

#[test]
fn conformance_e2e() {
    let Ok(url) = std::env::var("ONEPASS_MAILBOX_E2E_URL") else {
        println!("skipped: ONEPASS_MAILBOX_E2E_URL unset");
        return;
    };
    let admin = std::env::var_os("ONEPASS_MAILBOX_E2E_ADMIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../mailbox/scripts/e2e-admin.sh")
        });
    let mut target = E2e {
        endpoint: Endpoint {
            base_url: url,
            extra_ca_pem: None,
        },
        invite: std::env::var("ONEPASS_MAILBOX_E2E_INVITE")
            .ok()
            .map(String::into_bytes),
        admin,
    };

    run_conformance(&mut target);
    storage_duplicate_upload_is_success(&mut target);
    wrong_base_url_is_no_route(&mut target);
    commit_wakes_the_listener(&mut target);
}

/// A commit on the real stack reaches a `WakeListener` on the mailbox's
/// wake topic through Realtime (`onepass_mailbox_wake.send`, spec 4.10),
/// whatever payload `realtime.send` puts in the message.
fn commit_wakes_the_listener(t: &mut E2e) {
    t.before_case();
    let mut c = t.mailbox_client();
    let invite = t.invite.clone();
    let created = c.create(invite.as_deref(), b"wake").expect("create");
    let config = c.server_config().expect("config");
    let wakes = Arc::new(AtomicUsize::new(0));
    let w = Arc::clone(&wakes);
    let listener = WakeListener::start(
        &config.realtime_url,
        &config.publishable_key,
        created.wake_topic,
        Box::new(move || {
            w.fetch_add(1, Ordering::SeqCst);
        }),
    )
    .expect("start the listener");
    let op = |n: u8| CommitOp {
        kind: 5,
        id: [n; 16],
        version: 1,
        op: Op::Put {
            expected: None,
            body: Body::Inline(vec![n]),
        },
    };
    // The join takes a moment: commit until a wake comes back.
    let until = Instant::now() + Duration::from_secs(30);
    let mut n = 1u8;
    while wakes.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < until, "no wake within 30 s");
        c.commit(vec![op(n)]).expect("commit");
        n += 1;
        std::thread::sleep(Duration::from_secs(1));
    }
    listener.stop();
    eprintln!("commit wakes the listener: ok ({n} commits)");
}

/// Storage answers a second upload to the same signed URL (x-upsert false)
/// with its duplicate status: the client must take it as success.
fn storage_duplicate_upload_is_success(t: &mut E2e) {
    t.before_case();
    let mut c = t.mailbox_client();
    let invite = t.invite.clone();
    c.create(invite.as_deref(), b"storage").expect("create");
    let data: Vec<u8> = (0..20 * 1024u32).map(|i| (i % 251) as u8).collect();
    let sha = blob_sha256(&data);
    let urls = c
        .testing_announce(&[(sha, data.len() as u32)])
        .expect("announce");
    let url = urls.urls[0].1.clone().expect("a new blob needs an upload");
    c.testing_put_object(&url, &data).expect("first upload");
    c.testing_put_object(&url, &data)
        .expect("second upload of the same object: Storage's duplicate answer is success");
    // The object is there: a new announce asks for no upload.
    let again = c
        .testing_announce(&[(sha, data.len() as u32)])
        .expect("announce again");
    assert_eq!(again.urls[0].1, None, "object present, no upload URL");
    eprintln!("storage duplicate upload: ok");
}

/// A base URL the function does not serve answers `no_route`, never the
/// `not_found` of an absent record.
fn wrong_base_url_is_no_route(t: &mut E2e) {
    t.before_case();
    let mut owner = t.mailbox_client();
    let invite = t.invite.clone();
    owner.create(invite.as_deref(), b"route").expect("create");
    assert_eq!(owner.record(5, [1; 16]).expect("absent record"), None);
    let wrong = Endpoint {
        base_url: format!("{}/v2", t.endpoint.base_url),
        extra_ca_pem: None,
    };
    let mut c = MailboxClient::new(wrong, Credential::generate().unwrap()).unwrap();
    c.open(owner.mailbox().expect("open"));
    match c.record(5, [1; 16]) {
        Err(MailboxError::Server(ErrorCode::NoRoute)) => {}
        other => panic!("wrong base URL: {other:?}"),
    }
    eprintln!("no_route against not_found: ok");
}
