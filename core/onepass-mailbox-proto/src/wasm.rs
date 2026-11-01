//! WebAssembly exports for the mailbox edge function (feature `wasm`, built
//! by `mailbox/scripts/build-proto-wasm.sh`). The edge function calls these
//! and never re-implements decoding or the signature base.
//!
//! JavaScript shapes (serde-wasm-bindgen): byte fields are `Uint8Array`,
//! `u64` and `i64` are `BigInt`, smaller integers are `Number`, `None` is
//! `null`, enums are externally tagged (`{ Put: {...} }`, `"Delete"`).
//! Every failure throws an `Error` whose message is the `ProtoError` text.

use std::fmt::Display;

use serde::Serialize;
use serde::de::DeserializeOwned;
use wasm_bindgen::prelude::*;

use crate::{
    BlobAnnounce, BlobLookup, BlobUrls, ChangesPage, ChangesQuery, CommitRequest, CommitResponse,
    CreateMailbox, Enroll, EnrollTicket, ErrorBody, GrantCredential, LocateRequest, Located,
    MailboxCreated, MailboxInfo, Message, ServerConfig, ServerRecord, SetCredentialRole,
    SetLocator, SetPush, SignatureParams, SignedEnrollTicket, decode, encode,
};

fn err(e: impl Display) -> JsError {
    JsError::new(&e.to_string())
}

fn to_js<T: Serialize>(v: &T) -> Result<JsValue, JsError> {
    let ser = serde_wasm_bindgen::Serializer::new()
        .serialize_missing_as_null(true)
        .serialize_large_number_types_as_bigints(true);
    v.serialize(&ser).map_err(err)
}

fn from_js<T: DeserializeOwned>(v: JsValue) -> Result<T, JsError> {
    serde_wasm_bindgen::from_value(v).map_err(err)
}

fn dec<M: Message>(bytes: &[u8]) -> Result<JsValue, JsError> {
    to_js(&decode::<M>(bytes).map_err(err)?)
}

/// What the edge function sends goes through the same strict decoder the
/// client runs, so a server bug (an unsorted list, a cap) fails here first.
fn enc<M: Message>(v: JsValue) -> Result<Vec<u8>, JsError> {
    let bytes = encode(&from_js::<M>(v)?);
    decode::<M>(&bytes).map_err(err)?;
    Ok(bytes)
}

#[wasm_bindgen(js_name = decodeCommit)]
pub fn decode_commit(bytes: &[u8]) -> Result<JsValue, JsError> {
    dec::<CommitRequest>(bytes)
}

#[wasm_bindgen(js_name = decodeCreate)]
pub fn decode_create(bytes: &[u8]) -> Result<JsValue, JsError> {
    dec::<CreateMailbox>(bytes)
}

#[wasm_bindgen(js_name = decodeEnroll)]
pub fn decode_enroll(bytes: &[u8]) -> Result<JsValue, JsError> {
    dec::<Enroll>(bytes)
}

#[wasm_bindgen(js_name = decodeSetPush)]
pub fn decode_set_push(bytes: &[u8]) -> Result<JsValue, JsError> {
    dec::<SetPush>(bytes)
}

/// `{ public_key, role: "Read" | "Write" | "Manage", put_kinds, label }`.
#[wasm_bindgen(js_name = decodeGrant)]
pub fn decode_grant(bytes: &[u8]) -> Result<JsValue, JsError> {
    dec::<GrantCredential>(bytes)
}

/// `{ role, put_kinds }`.
#[wasm_bindgen(js_name = decodeSetRole)]
pub fn decode_set_role(bytes: &[u8]) -> Result<JsValue, JsError> {
    dec::<SetCredentialRole>(bytes)
}

/// `{ locator }`.
#[wasm_bindgen(js_name = decodeSetLocator)]
pub fn decode_set_locator(bytes: &[u8]) -> Result<JsValue, JsError> {
    dec::<SetLocator>(bytes)
}

#[wasm_bindgen(js_name = decodeBlobAnnounce)]
pub fn decode_blob_announce(bytes: &[u8]) -> Result<JsValue, JsError> {
    dec::<BlobAnnounce>(bytes)
}

#[wasm_bindgen(js_name = decodeBlobLookup)]
pub fn decode_blob_lookup(bytes: &[u8]) -> Result<JsValue, JsError> {
    dec::<BlobLookup>(bytes)
}

/// `{ after, limit, full }` from the query string of `GET .../changes`
/// (without the `?`), in its only accepted spelling.
#[wasm_bindgen(js_name = parseChangesQuery)]
pub fn parse_changes_query(query: &str) -> Result<JsValue, JsError> {
    to_js(&ChangesQuery::parse(query).map_err(err)?)
}

#[wasm_bindgen(js_name = encodeChanges)]
pub fn encode_changes(v: JsValue) -> Result<Vec<u8>, JsError> {
    enc::<ChangesPage>(v)
}

#[wasm_bindgen(js_name = encodeRecord)]
pub fn encode_record(v: JsValue) -> Result<Vec<u8>, JsError> {
    enc::<ServerRecord>(v)
}

#[wasm_bindgen(js_name = encodeCommitResponse)]
pub fn encode_commit_response(v: JsValue) -> Result<Vec<u8>, JsError> {
    enc::<CommitResponse>(v)
}

#[wasm_bindgen(js_name = encodeCreated)]
pub fn encode_created(v: JsValue) -> Result<Vec<u8>, JsError> {
    enc::<MailboxCreated>(v)
}

#[wasm_bindgen(js_name = encodeInfo)]
pub fn encode_info(v: JsValue) -> Result<Vec<u8>, JsError> {
    enc::<MailboxInfo>(v)
}

#[wasm_bindgen(js_name = encodeConfig)]
pub fn encode_config(v: JsValue) -> Result<Vec<u8>, JsError> {
    enc::<ServerConfig>(v)
}

#[wasm_bindgen(js_name = encodeBlobUrls)]
pub fn encode_blob_urls(v: JsValue) -> Result<Vec<u8>, JsError> {
    enc::<BlobUrls>(v)
}

/// `{ mailbox_id }`.
#[wasm_bindgen(js_name = decodeLocateRequest)]
pub fn decode_locate_request(bytes: &[u8]) -> Result<JsValue, JsError> {
    dec::<LocateRequest>(bytes)
}

#[wasm_bindgen(js_name = encodeLocated)]
pub fn encode_located(v: JsValue) -> Result<Vec<u8>, JsError> {
    enc::<Located>(v)
}

#[wasm_bindgen(js_name = encodeError)]
pub fn encode_error(v: JsValue) -> Result<Vec<u8>, JsError> {
    enc::<ErrorBody>(v)
}

/// `params` is the `params` object `parseSignatureHeaders` returned.
#[wasm_bindgen(js_name = signatureBase)]
pub fn signature_base(
    method: &str,
    target: &str,
    content_digest: &str,
    params: JsValue,
) -> Result<Vec<u8>, JsError> {
    let p: SignatureParams = from_js(params)?;
    crate::signature_base(method, target, content_digest, &p).map_err(err)
}

/// `{ params: { created, nonce, keyid }, sig }`.
#[wasm_bindgen(js_name = parseSignatureHeaders)]
pub fn parse_signature_headers(signature_input: &str, signature: &str) -> Result<JsValue, JsError> {
    to_js(&crate::parse_signature_headers(signature_input, signature).map_err(err)?)
}

#[wasm_bindgen(js_name = contentDigest)]
pub fn content_digest(body: &[u8]) -> String {
    crate::content_digest(body)
}

#[wasm_bindgen(js_name = credentialId)]
pub fn credential_id(public_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let pk: crate::CredentialPublicKey = public_key
        .try_into()
        .map_err(|_| JsError::new("public key length"))?;
    Ok(crate::credential_id(&pk).to_vec())
}

/// `ticket` is `decodeEnroll(...).ticket.ticket`.
#[wasm_bindgen(js_name = ticketSignedBytes)]
pub fn ticket_signed_bytes(ticket: JsValue) -> Result<Vec<u8>, JsError> {
    let t: EnrollTicket = from_js(ticket)?;
    t.check().map_err(err)?;
    Ok(crate::ticket_signed_bytes(&t))
}

/// `signed` is `decodeEnroll(...).ticket`.
#[wasm_bindgen(js_name = ticketHash)]
pub fn ticket_hash(signed: JsValue) -> Result<Vec<u8>, JsError> {
    let t: SignedEnrollTicket = from_js(signed)?;
    t.ticket.check().map_err(err)?;
    Ok(crate::ticket_hash(&t).to_vec())
}

/// Throws when `|now - created| > SKEW_SECS`. Both are `BigInt`.
#[wasm_bindgen(js_name = checkSkew)]
pub fn check_skew(created: i64, now: i64) -> Result<(), JsError> {
    crate::check_skew(created, now).map_err(err)
}

#[wasm_bindgen(js_name = checkTicketTimes)]
pub fn check_ticket_times(ticket: JsValue, now: i64) -> Result<(), JsError> {
    let t: EnrollTicket = from_js(ticket)?;
    crate::check_ticket_times(&t, now).map_err(err)
}
