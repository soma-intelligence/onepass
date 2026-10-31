//! Record bodies above 16 KiB go through Storage (spec 4.11): announced,
//! uploaded to the signed URL the mailbox hands back, referenced by hash in
//! the commit, and checked against that hash when read back.

use std::collections::BTreeMap;

use onepass_mailbox_proto::{
    BlobAnnounce, BlobLookup, BlobUrls, Body, CommitOp, CommitResponse, ErrorCode, INLINE_MAX, Op,
    PAGE_MAX_RECORDS, RECORD_MAX, Sha256, blob_sha256, encode,
};

use crate::client::{MailboxClient, expect, read};
use crate::http::{Method, Response, check_url};
use crate::{MailboxApi, MailboxError};

const OCTETS: &str = "application/octet-stream";

impl MailboxClient {
    /// The body a record of `data` goes out with: inline up to `INLINE_MAX`
    /// (16 KiB) included, a blob reference up to `RECORD_MAX` (900 KiB),
    /// `TooLarge` above.
    pub fn body_for(&self, data: &[u8]) -> Result<Body, MailboxError> {
        body_for(data)
    }

    /// Announces the blobs (1000 per request at most), then uploads those
    /// the mailbox does not hold yet. Every one must be a blob body, above
    /// 16 KiB and at most 900 KiB.
    pub fn upload_blobs(&self, blobs: &[&[u8]]) -> Result<(), MailboxError> {
        let all = blob_set(blobs)?;
        for chunk in all.chunks(PAGE_MAX_RECORDS as usize) {
            let announced: Vec<(Sha256, u32)> = chunk
                .iter()
                // Sizes fit: each is at most RECORD_MAX.
                .map(|(h, d)| (*h, d.len() as u32))
                .collect();
            let urls = self.announce(&announced)?;
            for ((_, data), (_, url)) in chunk.iter().zip(&urls.urls) {
                if let Some(url) = url {
                    self.put_object(url, data)?;
                }
            }
        }
        Ok(())
    }

    /// The bytes of a record body. A blob is fetched from a signed URL and
    /// handed back only if its size and SHA-256 are the ones it is named by
    /// (`Integrity("blob")` otherwise).
    pub fn fetch_body(&self, body: &Body) -> Result<Vec<u8>, MailboxError> {
        let (sha256, size) = match blob_of(body)? {
            BodyRef::Inline(d) => return Ok(d.to_vec()),
            BodyRef::Blob { sha256, size } => (sha256, size),
        };
        let target = format!("{}/blobs/downloads", self.mailbox_path()?);
        let lookup = BlobLookup {
            blobs: vec![sha256],
        };
        let r = expect(
            self.signed(Method::Post, &target, &encode(&lookup))?,
            &[200],
        )?;
        let urls: BlobUrls = read(r)?;
        check_answers(&urls, &[sha256])?;
        let url = urls.urls[0]
            .1
            .as_deref()
            .ok_or(MailboxError::Server(ErrorCode::NotFound))?;
        check_url(url, true).map_err(|_| MailboxError::Malformed("blob url"))?;
        let r = match self
            .http()
            .send(Method::Get, url, &[], &[], u64::from(size) + 1)
        {
            Err(MailboxError::Malformed("response size")) => {
                return Err(MailboxError::Integrity("blob"));
            }
            r => storage_status(r?, &[200])?,
        };
        check_blob(sha256, size, &r.body)?;
        Ok(r.body)
    }

    /// `commit` for a batch that names blobs: uploads the ones it names
    /// (each must be in `blobs`), commits, and if the commit is answered
    /// malformed (a blob collected between announce and commit, spec 4.11)
    /// announces, uploads and commits once more.
    pub fn commit_with_blobs(
        &self,
        ops: Vec<CommitOp>,
        blobs: &[&[u8]],
    ) -> Result<CommitResponse, MailboxError> {
        commit_with_blobs(self, ops, blobs)
    }

    /// `POST /v1/mailboxes/{m}/blobs/uploads` for one chunk (1000 at most,
    /// sorted by hash, distinct): the answer lists exactly these hashes, in
    /// order, and every URL in it passes the URL check.
    fn announce(&self, blobs: &[(Sha256, u32)]) -> Result<BlobUrls, MailboxError> {
        let target = format!("{}/blobs/uploads", self.mailbox_path()?);
        let announce = BlobAnnounce {
            blobs: blobs.to_vec(),
        };
        let r = expect(
            self.signed(Method::Post, &target, &encode(&announce))?,
            &[200],
        )?;
        let urls: BlobUrls = read(r)?;
        let hashes: Vec<Sha256> = blobs.iter().map(|(h, _)| *h).collect();
        check_answers(&urls, &hashes)?;
        for (_, url) in &urls.urls {
            if let Some(u) = url {
                check_url(u, true).map_err(|_| MailboxError::Malformed("blob url"))?;
            }
        }
        Ok(urls)
    }

    fn put_object(&self, url: &str, data: &[u8]) -> Result<(), MailboxError> {
        let headers = [
            ("content-type", OCTETS.to_string()),
            ("x-upsert", "false".to_string()),
        ];
        let r = self
            .http()
            .send(Method::Put, url, &headers, data, 64 * 1024)?;
        upload_status(r)
    }
}

/// Low-level blob steps for end-to-end tests of Storage itself (a second
/// upload to the same signed URL must count as success).
#[cfg(feature = "testing")]
impl MailboxClient {
    pub fn testing_announce(&self, blobs: &[(Sha256, u32)]) -> Result<BlobUrls, MailboxError> {
        self.announce(blobs)
    }

    pub fn testing_put_object(&self, url: &str, data: &[u8]) -> Result<(), MailboxError> {
        self.put_object(url, data)
    }
}

/// The body a record of `data` goes out with (see `MailboxClient::body_for`).
pub(crate) fn body_for(data: &[u8]) -> Result<Body, MailboxError> {
    if data.len() <= INLINE_MAX {
        return Ok(Body::Inline(data.to_vec()));
    }
    if data.len() > RECORD_MAX {
        return Err(MailboxError::TooLarge);
    }
    Ok(Body::Blob {
        sha256: blob_sha256(data),
        size: u32::try_from(data.len()).map_err(|_| MailboxError::TooLarge)?,
    })
}

/// The blobs to upload, each above 16 KiB and at most 900 KiB, once each,
/// sorted by hash.
pub(crate) fn blob_set<'a>(blobs: &[&'a [u8]]) -> Result<Vec<(Sha256, &'a [u8])>, MailboxError> {
    let mut by_hash: BTreeMap<Sha256, &[u8]> = BTreeMap::new();
    for b in blobs {
        if b.len() <= INLINE_MAX {
            return Err(MailboxError::Malformed("inline body given as a blob"));
        }
        if b.len() > RECORD_MAX {
            return Err(MailboxError::TooLarge);
        }
        by_hash.insert(blob_sha256(b), b);
    }
    Ok(by_hash.into_iter().collect())
}

pub(crate) enum BodyRef<'a> {
    Inline(&'a [u8]),
    Blob { sha256: Sha256, size: u32 },
}

/// A body read from the server, within the protocol's bounds.
pub(crate) fn blob_of(body: &Body) -> Result<BodyRef<'_>, MailboxError> {
    match body {
        Body::Inline(d) if d.len() <= INLINE_MAX => Ok(BodyRef::Inline(d)),
        Body::Inline(_) => Err(MailboxError::Malformed("inline body too long")),
        Body::Blob { size, .. } if *size as usize > RECORD_MAX => {
            Err(MailboxError::Malformed("blob size"))
        }
        Body::Blob { sha256, size } => Ok(BodyRef::Blob {
            sha256: *sha256,
            size: *size,
        }),
    }
}

/// Bytes read back for a blob: exactly its size and its SHA-256.
pub(crate) fn check_blob(sha256: Sha256, size: u32, data: &[u8]) -> Result<(), MailboxError> {
    if data.len() != size as usize || blob_sha256(data) != sha256 {
        return Err(MailboxError::Integrity("blob"));
    }
    Ok(())
}

/// `commit_with_blobs` on any mailbox API (the real client and the
/// in-memory one behave the same).
pub(crate) fn commit_with_blobs<A: MailboxApi + ?Sized>(
    api: &A,
    ops: Vec<CommitOp>,
    blobs: &[&[u8]],
) -> Result<CommitResponse, MailboxError> {
    let given: BTreeMap<Sha256, &[u8]> = blobs.iter().map(|b| (blob_sha256(b), *b)).collect();
    let mut named: BTreeMap<Sha256, &[u8]> = BTreeMap::new();
    for o in &ops {
        if let Op::Put {
            body: Body::Blob { sha256, size },
            ..
        } = &o.op
        {
            let data = given
                .get(sha256)
                .filter(|d| d.len() == *size as usize)
                .ok_or(MailboxError::Malformed("blob not given"))?;
            named.insert(*sha256, data);
        }
    }
    let named: Vec<&[u8]> = named.into_values().collect();
    if named.is_empty() {
        return api.commit(ops);
    }
    api.upload_blobs(&named)?;
    match api.commit(ops.clone()) {
        Err(MailboxError::Server(ErrorCode::Malformed)) => {
            api.upload_blobs(&named)?;
            api.commit(ops)
        }
        r => r,
    }
}

/// One answer per hash asked, in the same (sorted) order.
pub(crate) fn check_answers(urls: &BlobUrls, asked: &[Sha256]) -> Result<(), MailboxError> {
    if urls.urls.len() != asked.len() || urls.urls.iter().zip(asked).any(|(u, h)| u.0 != *h) {
        return Err(MailboxError::Malformed("blob urls"));
    }
    Ok(())
}

/// An upload answer. The object already being there under this exact name
/// is success: older Storage says `409`, Storage v1.84 (Supabase CLI
/// 2.122.0) says `400` with the JSON body `{"statusCode":"409","error":
/// "Duplicate",...}`. A server that lies here only makes the commit that
/// follows fail as malformed (the object is checked there).
fn upload_status(r: Response) -> Result<(), MailboxError> {
    if r.status == 400 && duplicate_body(&r.body) {
        return Ok(());
    }
    storage_status(r, &[200, 201, 409]).map(|_| ())
}

/// The body carries `"statusCode":"409"` (JSON whitespace aside).
fn duplicate_body(body: &[u8]) -> bool {
    let compact: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let needle = br#""statusCode":"409""#;
    compact.windows(needle.len()).any(|w| w == needle)
}

/// Storage answers are not the mailbox's postcard: by status only.
fn storage_status(r: Response, ok: &[u16]) -> Result<Response, MailboxError> {
    match r.status {
        s if ok.contains(&s) => Ok(r),
        404 => Err(MailboxError::Server(ErrorCode::NotFound)),
        429 => Err(MailboxError::Retry {
            after: r.retry_after,
        }),
        500..=599 => Err(MailboxError::Retry { after: None }),
        300..=399 => Err(MailboxError::Malformed("redirect")),
        _ => Err(MailboxError::Malformed("storage status")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, body: &str) -> Response {
        Response {
            status,
            content_type: Some("application/json".into()),
            retry_after: None,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn duplicate_upload_is_success() {
        // Storage v1.84 (the CLI 2.122.0 stack): 400 with a JSON body that
        // carries the 409, seen live on the local stack.
        let live = r#"{"statusCode":"409","error":"Duplicate","message":"The resource already exists","code":"KeyAlreadyExists"}"#;
        assert!(upload_status(answer(400, live)).is_ok());
        assert!(
            upload_status(answer(
                400,
                r#"{ "statusCode": "409", "error": "Duplicate" }"#
            ))
            .is_ok()
        );
        // Older Storage: a plain 409.
        assert!(upload_status(answer(409, "")).is_ok());
        assert!(upload_status(answer(200, "")).is_ok());
        assert!(upload_status(answer(201, "")).is_ok());
    }

    #[test]
    fn other_upload_refusals_stay_errors() {
        for body in [
            r#"{"statusCode":"400","error":"InvalidRequest"}"#,
            r#"{"statusCode":"4090","error":"Duplicate"}"#,
            r#"{"statusCode":"403","error":"Unauthorized"}"#,
            "",
        ] {
            assert_eq!(
                upload_status(answer(400, body)).err(),
                Some(MailboxError::Malformed("storage status")),
                "{body}"
            );
        }
        assert_eq!(
            upload_status(answer(403, r#"{"statusCode":"409"}"#)).err(),
            Some(MailboxError::Malformed("storage status"))
        );
    }
}
