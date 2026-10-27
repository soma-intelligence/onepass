//! Namespace of an SSHSIG signature request (`ssh-keygen -Y sign`, Git
//! commit signing), shown in the approval prompt (spec 6.3).
//!
//! The data an agent signs for SSHSIG (PROTOCOL.sshsig) is the 6-byte magic
//! `SSHSIG` followed by `string namespace`, `string reserved`, `string
//! hash_algorithm` and `string H(message)`.

use crate::wire::SshReader;

const MAGIC: &[u8] = b"SSHSIG";

/// The namespace of SSHSIG signed data, or `None` when `data` is not a
/// well-formed SSHSIG blob (an SSH authentication request, for example).
pub fn sshsig_namespace(data: &[u8]) -> Option<String> {
    let rest = data.strip_prefix(MAGIC)?;
    let mut r = SshReader::new(rest);
    let namespace = r.utf8().ok()?;
    r.string().ok()?;
    r.utf8().ok()?;
    r.string().ok()?;
    r.finish().ok()?;
    Some(namespace.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::SshWriter;

    fn blob(namespace: &str) -> Vec<u8> {
        let mut w = SshWriter::new();
        w.raw(MAGIC)
            .string(namespace.as_bytes())
            .string(b"")
            .string(b"sha512")
            .string(&[7u8; 64]);
        w.into_vec()
    }

    #[test]
    fn reads_namespace() {
        assert_eq!(sshsig_namespace(&blob("git")).as_deref(), Some("git"));
        assert_eq!(sshsig_namespace(&blob("file")).as_deref(), Some("file"));
    }

    #[test]
    fn rejects_other_data() {
        assert_eq!(sshsig_namespace(b""), None);
        assert_eq!(sshsig_namespace(b"SSHSIG"), None);
        let mut trailing = blob("git");
        trailing.push(0);
        assert_eq!(sshsig_namespace(&trailing), None);
        // An SSH userauth request starts with the session id string.
        let mut w = SshWriter::new();
        w.string(&[1u8; 32]).u8(50);
        assert_eq!(sshsig_namespace(w.as_slice()), None);
    }
}
