//! Record bodies above 16 KiB go through Storage (spec 4.11): announced,
//! uploaded to the signed URL the mailbox hands back, referenced by hash in
//! the commit, and checked against that hash when read back.

use std::collections::BTreeMap;

use onepass_mailbox_proto::{
    BlobAnnounce, BlobLookup, BlobUrls, Body, CommitOp, CommitResponse, ErrorCode, INLINE_MAX, Op,
    PAGE_MAX_RECORDS, RECORD_MAX, Sha256, blob_sha256, encode,
};

use crate::MailboxError;
use crate::client::{MailboxClient, expect, read};
use crate::http::{Method, Response, check_url};

const OCTETS: &str = "application/octet-stream";

impl MailboxClient {
    /// The body a record of `data` goes out with: inline up to `INLINE_MAX`
    /// (16 KiB) included, a blob reference up to `RECORD_MAX` (900 KiB),
    /// `TooLarge` above.
    pub fn body_for(&self, data: &[u8]) -> Result<Body, MailboxError> {
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

    /// Announces the blobs (1000 per request at most), then uploads those
    /// the mailbox does not hold yet. Every one must be a blob body, above
    /// 16 KiB and at most 900 KiB.
    pub fn upload_blobs(&self, blobs: &[&[u8]]) -> Result<(), MailboxError> {
        let target = format!("{}/blobs/uploads", self.mailbox_path()?);
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
        let all: Vec<(Sha256, &[u8])> = by_hash.into_iter().collect();
        for chunk in all.chunks(PAGE_MAX_RECORDS as usize) {
            let announce = BlobAnnounce {
                // Sizes fit: each is at most RECORD_MAX.
                blobs: chunk.iter().map(|(h, d)| (*h, d.len() as u32)).collect(),
            };
            let r = expect(
                self.signed(Method::Post, &target, &encode(&announce))?,
                &[200],
            )?;
            let urls: BlobUrls = read(r)?;
            let hashes: Vec<Sha256> = chunk.iter().map(|(h, _)| *h).collect();
            check_answers(&urls, &hashes)?;
            for (_, url) in &urls.urls {
                if let Some(u) = url {
                    check_url(u, true).map_err(|_| MailboxError::Malformed("blob url"))?;
                }
            }
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
        let (sha256, size) = match body {
            Body::Inline(d) if d.len() <= INLINE_MAX => return Ok(d.clone()),
            Body::Inline(_) => return Err(MailboxError::Malformed("inline body too long")),
            Body::Blob { sha256, size } => (*sha256, *size),
        };
        if size as usize > RECORD_MAX {
            return Err(MailboxError::Malformed("blob size"));
        }
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
        if r.body.len() != size as usize || blob_sha256(&r.body) != sha256 {
            return Err(MailboxError::Integrity("blob"));
        }
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
            return self.commit(ops);
        }
        self.upload_blobs(&named)?;
        match self.commit(ops.clone()) {
            Err(MailboxError::Server(ErrorCode::Malformed)) => {
                self.upload_blobs(&named)?;
                self.commit(ops)
            }
            r => r,
        }
    }

    fn put_object(&self, url: &str, data: &[u8]) -> Result<(), MailboxError> {
        let headers = [
            ("content-type", OCTETS.to_string()),
            ("x-upsert", "false".to_string()),
        ];
        let r = self
            .http()
            .send(Method::Put, url, &headers, data, 64 * 1024)?;
        // 409: the object is already there under this exact name.
        storage_status(r, &[200, 201, 409]).map(|_| ())
    }
}

/// One answer per hash asked, in the same (sorted) order.
fn check_answers(urls: &BlobUrls, asked: &[Sha256]) -> Result<(), MailboxError> {
    if urls.urls.len() != asked.len() || urls.urls.iter().zip(asked).any(|(u, h)| u.0 != *h) {
        return Err(MailboxError::Malformed("blob urls"));
    }
    Ok(())
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
