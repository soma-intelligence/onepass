//! Text armor (PEM, RFC 7468) and the OpenSSH private key container
//! (`openssh-key-v1`, OpenSSH `PROTOCOL.key`), including decryption with
//! bcrypt-pbkdf and AES (CTR, CBC, GCM) through aws-lc-rs.

use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::cipher::{self, DecryptingKey, DecryptionContext, UnboundCipherKey};
use aws_lc_rs::iv::FixedLength;
use data_encoding::BASE64;
use zeroize::Zeroizing;

use crate::keys::KeyError;
use crate::wire::{SshReader, SshWriter};

pub(crate) const OPENSSH_LABEL: &str = "OPENSSH PRIVATE KEY";
const MAGIC: &[u8] = b"openssh-key-v1\0";
/// Upper bound on bcrypt-pbkdf rounds read from a file, so a hostile file
/// cannot stall the process (ssh-keygen defaults to 16).
const MAX_BCRYPT_ROUNDS: u32 = 1024;
const GCM_TAG_LEN: usize = 16;

/// A PEM block found in a text.
pub(crate) struct Pem {
    pub(crate) label: String,
    /// Whether RFC 1421 headers announce encryption (`Proc-Type: 4,ENCRYPTED`).
    pub(crate) encrypted_headers: bool,
    pub(crate) der: Zeroizing<Vec<u8>>,
}

/// Finds the first PEM block whose label is accepted by `want`. Other
/// blocks (such as `EC PARAMETERS`) are skipped.
pub(crate) fn pem_find(text: &str, want: impl Fn(&str) -> bool) -> Result<Option<Pem>, KeyError> {
    let mut lines = text.lines().map(str::trim);
    while let Some(line) = lines.next() {
        let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
        else {
            continue;
        };
        if !want(label) {
            continue;
        }
        let end = format!("-----END {label}-----");
        // Sized from the whole text so pushing never reallocates.
        let mut b64 = Zeroizing::new(String::with_capacity(text.len()));
        let mut encrypted_headers = false;
        let mut closed = false;
        for l in lines.by_ref() {
            if l == end {
                closed = true;
                break;
            }
            if l.contains(':') {
                encrypted_headers |= l.starts_with("Proc-Type:") && l.contains("ENCRYPTED");
                continue;
            }
            b64.push_str(l);
        }
        if !closed {
            return Err(KeyError::BadKey);
        }
        let der = Zeroizing::new(
            BASE64
                .decode(b64.as_bytes())
                .map_err(|_| KeyError::BadKey)?,
        );
        return Ok(Some(Pem {
            label: label.to_owned(),
            encrypted_headers,
            der,
        }));
    }
    Ok(None)
}

/// PEM armor with lines of `width` characters and a final newline.
pub(crate) fn pem_encode(label: &str, der: &[u8], width: usize) -> Zeroizing<String> {
    let b64 = Zeroizing::new(BASE64.encode(der));
    // Exact size: base64, one newline per line, "-----BEGIN -----\n" (17)
    // and "-----END -----\n" (15) around two copies of the label.
    let capacity = b64.len() + b64.len().div_ceil(width) + 2 * label.len() + 32;
    let mut out = Zeroizing::new(String::with_capacity(capacity));
    let initial = out.capacity();
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in b64.as_bytes().chunks(width) {
        // Base64 output is ASCII, so every chunk is valid UTF-8.
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    debug_assert_eq!(out.capacity(), initial, "PEM buffer reallocated");
    out
}

/// The fields of an `openssh-key-v1` container holding one key.
pub(crate) struct Container<'a> {
    pub(crate) cipher: &'a str,
    kdf: &'a str,
    kdf_options: &'a [u8],
    pub(crate) public: &'a [u8],
    private: &'a [u8],
    tag: &'a [u8],
}

impl<'a> Container<'a> {
    pub(crate) fn parse(bin: &'a [u8]) -> Result<Self, KeyError> {
        let body = bin.strip_prefix(MAGIC).ok_or(KeyError::BadKey)?;
        let mut r = SshReader::new(body);
        let bad = |_| KeyError::BadKey;
        let cipher = r.utf8().map_err(bad)?;
        let kdf = r.utf8().map_err(bad)?;
        let kdf_options = r.string().map_err(bad)?;
        if r.u32().map_err(bad)? != 1 {
            return Err(KeyError::Unsupported("several keys in one file"));
        }
        let public = r.string().map_err(bad)?;
        let private = r.string().map_err(bad)?;
        let tag = r.rest();
        Ok(Self {
            cipher,
            kdf,
            kdf_options,
            public,
            private,
            tag,
        })
    }

    pub(crate) fn is_encrypted(&self) -> bool {
        self.cipher != "none"
    }

    /// Returns the plaintext private section (check integers, key, comment,
    /// padding).
    pub(crate) fn private_section(
        &self,
        passphrase: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        if !self.is_encrypted() {
            if self.kdf != "none"
                || !self.kdf_options.is_empty()
                || !self.tag.is_empty()
                || !self.private.len().is_multiple_of(8)
            {
                return Err(KeyError::BadKey);
            }
            return Ok(Zeroizing::new(self.private.to_vec()));
        }
        let suite = Suite::from_name(self.cipher)?;
        if self.kdf != "bcrypt" {
            return Err(KeyError::Unsupported("OpenSSH key derivation"));
        }
        let mut opts = SshReader::new(self.kdf_options);
        let salt = opts.string().map_err(|_| KeyError::BadKey)?;
        let rounds = opts.u32().map_err(|_| KeyError::BadKey)?;
        opts.finish().map_err(|_| KeyError::BadKey)?;
        if rounds == 0 || salt.is_empty() {
            return Err(KeyError::BadKey);
        }
        if rounds > MAX_BCRYPT_ROUNDS {
            return Err(KeyError::Unsupported("bcrypt rounds above 1024"));
        }
        let passphrase = passphrase.ok_or(KeyError::NeedPassphrase)?;
        if passphrase.is_empty() {
            return Err(KeyError::BadPassphrase);
        }
        let expected_tag = if suite.mode == Mode::Gcm {
            GCM_TAG_LEN
        } else {
            0
        };
        if self.tag.len() != expected_tag || !self.private.len().is_multiple_of(16) {
            return Err(KeyError::BadKey);
        }

        let mut key_iv = Zeroizing::new(vec![0u8; suite.key_len + suite.iv_len]);
        bcrypt_pbkdf::bcrypt_pbkdf(passphrase.as_bytes(), salt, rounds, &mut key_iv)
            .map_err(|_| KeyError::Crypto)?;
        let (key, iv) = key_iv.split_at(suite.key_len);

        // Room for the GCM tag, so appending it never reallocates.
        let mut buf = Zeroizing::new(Vec::with_capacity(self.private.len() + self.tag.len()));
        buf.extend_from_slice(self.private);
        match suite.mode {
            Mode::Ctr | Mode::Cbc => {
                let alg = match suite.key_len {
                    16 => &cipher::AES_128,
                    24 => &cipher::AES_192,
                    _ => &cipher::AES_256,
                };
                let unbound = UnboundCipherKey::new(alg, key).map_err(|_| KeyError::Crypto)?;
                let dk = if suite.mode == Mode::Ctr {
                    DecryptingKey::ctr(unbound)
                } else {
                    DecryptingKey::cbc(unbound)
                }
                .map_err(|_| KeyError::Crypto)?;
                let iv: [u8; 16] = iv.try_into().map_err(|_| KeyError::Crypto)?;
                let ctx = DecryptionContext::Iv128(FixedLength::from(iv));
                dk.decrypt(&mut buf, ctx).map_err(|_| KeyError::Crypto)?;
            }
            Mode::Gcm => {
                let alg = if suite.key_len == 16 {
                    &aead::AES_128_GCM
                } else {
                    &aead::AES_256_GCM
                };
                let k = LessSafeKey::new(UnboundKey::new(alg, key).map_err(|_| KeyError::Crypto)?);
                let nonce = Nonce::try_assume_unique_for_key(iv).map_err(|_| KeyError::Crypto)?;
                buf.extend_from_slice(self.tag);
                let plain_len = k
                    .open_in_place(nonce, Aad::empty(), &mut buf)
                    .map_err(|_| KeyError::BadPassphrase)?
                    .len();
                buf.truncate(plain_len);
            }
        }
        Ok(buf)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Ctr,
    Cbc,
    Gcm,
}

struct Suite {
    mode: Mode,
    key_len: usize,
    iv_len: usize,
}

impl Suite {
    fn from_name(name: &str) -> Result<Self, KeyError> {
        let (mode, key_len, iv_len) = match name {
            "aes128-ctr" => (Mode::Ctr, 16, 16),
            "aes192-ctr" => (Mode::Ctr, 24, 16),
            "aes256-ctr" => (Mode::Ctr, 32, 16),
            "aes128-cbc" => (Mode::Cbc, 16, 16),
            "aes192-cbc" => (Mode::Cbc, 24, 16),
            "aes256-cbc" => (Mode::Cbc, 32, 16),
            "aes128-gcm@openssh.com" => (Mode::Gcm, 16, 12),
            "aes256-gcm@openssh.com" => (Mode::Gcm, 32, 12),
            _ => return Err(KeyError::Unsupported("OpenSSH key cipher")),
        };
        Ok(Self {
            mode,
            key_len,
            iv_len,
        })
    }
}

/// Splits a plaintext private section into the key fields (starting with
/// the key type string) and checks the check integers and padding. Returns
/// a reader positioned on the key type.
pub(crate) fn open_private_section(section: &[u8]) -> Result<SshReader<'_>, KeyError> {
    let mut r = SshReader::new(section);
    let c1 = r.u32().map_err(|_| KeyError::BadKey)?;
    let c2 = r.u32().map_err(|_| KeyError::BadKey)?;
    if c1 != c2 {
        return Err(KeyError::BadPassphrase);
    }
    Ok(r)
}

/// Reads the comment and padding that close a private section.
pub(crate) fn close_private_section(mut r: SshReader<'_>) -> Result<(), KeyError> {
    r.string().map_err(|_| KeyError::BadKey)?; // comment, not kept
    let padding = r.rest();
    if padding.len() >= 255
        || padding
            .iter()
            .enumerate()
            .any(|(i, &b)| usize::from(b) != i + 1)
    {
        return Err(KeyError::BadKey);
    }
    Ok(())
}

/// Encodes an unencrypted `openssh-key-v1` container. `key_fields` starts
/// with the key type string, as in the private section.
pub(crate) fn encode_unencrypted(
    public_blob: &[u8],
    key_fields: &[u8],
    comment: &str,
) -> Result<Zeroizing<String>, KeyError> {
    let mut check = [0u8; 4];
    aws_lc_rs::rand::fill(&mut check).map_err(|_| KeyError::Crypto)?;
    let check = u32::from_be_bytes(check);

    // check integers, key fields, comment, then up to 7 padding bytes.
    let private_len = 8 + key_fields.len() + 4 + comment.len();
    let padded_len = private_len.next_multiple_of(8);
    let mut private = SshWriter::with_capacity(padded_len);
    let initial = private.capacity();
    private
        .u32(check)
        .u32(check)
        .raw(key_fields)
        .string(comment.as_bytes());
    for pad in 1..=(padded_len - private_len) {
        // At most 7, so the cast is lossless.
        private.u8(pad as u8);
    }
    debug_assert_eq!(private.capacity(), initial, "private section reallocated");
    let private = Zeroizing::new(private.into_vec());

    let out_len = MAGIC.len() + 4 * 7 + 8 + public_blob.len() + private.len();
    let mut out = SshWriter::with_capacity(out_len);
    let initial = out.capacity();
    out.raw(MAGIC)
        .string(b"none")
        .string(b"none")
        .string(b"")
        .u32(1)
        .string(public_blob)
        .string(&private);
    debug_assert_eq!(out.capacity(), initial, "container reallocated");
    let bin = Zeroizing::new(out.into_vec());
    Ok(pem_encode(OPENSSH_LABEL, &bin, 70))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_roundtrip_and_skips_other_blocks() {
        let data: Vec<u8> = (0..=255u8).collect();
        let pem = pem_encode("THING", &data, 70);
        assert!(pem.lines().skip(1).all(|l| l.len() <= 70));
        let text = format!(
            "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n{}",
            *pem
        );
        let found = pem_find(&text, |l| l == "THING").unwrap().unwrap();
        assert_eq!(found.label, "THING");
        assert!(!found.encrypted_headers);
        assert_eq!(*found.der, data);
        assert!(pem_find(&text, |l| l == "OTHER").unwrap().is_none());
    }

    #[test]
    fn pem_errors() {
        assert_eq!(
            pem_find("-----BEGIN X-----\nAAAA\n", |_| true).err(),
            Some(KeyError::BadKey)
        );
        assert_eq!(
            pem_find("-----BEGIN X-----\n!!!!\n-----END X-----\n", |_| true).err(),
            Some(KeyError::BadKey)
        );
        let enc = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        assert!(pem_find(enc, |_| true).unwrap().unwrap().encrypted_headers);
    }

    fn container(cipher: &str, kdf: &str, kdf_options: &[u8], private: &[u8]) -> Vec<u8> {
        let mut w = SshWriter::new();
        w.raw(MAGIC)
            .string(cipher.as_bytes())
            .string(kdf.as_bytes())
            .string(kdf_options)
            .u32(1)
            .string(b"public")
            .string(private);
        w.into_vec()
    }

    #[test]
    fn unencrypted_section_must_be_block_aligned() {
        for len in [8usize, 16] {
            let bin = container("none", "none", b"", &vec![0; len]);
            assert!(
                Container::parse(&bin)
                    .unwrap()
                    .private_section(None)
                    .is_ok()
            );
        }
        for len in [7usize, 9, 15] {
            let bin = container("none", "none", b"", &vec![0; len]);
            assert_eq!(
                Container::parse(&bin).unwrap().private_section(None).err(),
                Some(KeyError::BadKey),
                "length {len}"
            );
        }
    }

    #[test]
    fn bcrypt_rounds_are_capped() {
        let opts = |rounds: u32| {
            let mut w = SshWriter::new();
            w.string(b"0123456789abcdef").u32(rounds);
            w.into_vec()
        };
        let bin = container("aes256-ctr", "bcrypt", &opts(1025), &[0; 32]);
        assert_eq!(
            Container::parse(&bin)
                .unwrap()
                .private_section(Some("pw"))
                .err(),
            Some(KeyError::Unsupported("bcrypt rounds above 1024"))
        );
        // At the cap the derivation runs; random bytes fail the check later.
        let bin = container("aes256-ctr", "bcrypt", &opts(1), &[0; 32]);
        assert!(
            Container::parse(&bin)
                .unwrap()
                .private_section(Some("pw"))
                .is_ok()
        );
    }

    #[test]
    fn private_section_padding_is_checked() {
        let mut w = SshWriter::new();
        w.u32(7).u32(7).string(b"comment").raw(&[1, 2, 3]);
        let sec = w.into_vec();
        let r = open_private_section(&sec).unwrap();
        close_private_section(r).unwrap();

        let mut bad = sec.clone();
        *bad.last_mut().unwrap() = 4;
        let r = open_private_section(&bad).unwrap();
        assert_eq!(close_private_section(r), Err(KeyError::BadKey));

        let mut w = SshWriter::new();
        w.u32(7).u32(8);
        assert_eq!(
            open_private_section(w.as_slice()).err(),
            Some(KeyError::BadPassphrase)
        );
    }
}
