//! The tools' only way to the vaults: a narrow port over the repository,
//! so they can be tested over any implementation and never reach the
//! account or the store directly.

use onepass_core::model::Item;
use onepass_core::reference::SecretRef;
use onepass_core::repo::Repository;
use onepass_core::store::RecordStore;
use onepass_core::vault::Vault;
use onepass_core::{Error, Id};
use zeroize::Zeroizing;

/// What the tools learn about a vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultInfo {
    pub id: Id,
    pub name: String,
    pub mcp_access: bool,
}

/// A failed port call. Messages never carry a value or item content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortError {
    /// Nothing matches.
    NotFound,
    /// Stored data failed verification (authentication or decryption):
    /// the vault is quarantined for the session.
    Integrity,
    /// A rejected input: field and reason, never the value.
    Invalid(String),
    /// Anything else, with a non-sensitive message.
    Other(String),
}

impl From<Error> for PortError {
    fn from(e: Error) -> Self {
        match e {
            Error::NotFound => PortError::NotFound,
            Error::Integrity(_) | Error::Crypto => PortError::Integrity,
            // A value the core cannot interpret (an HOTP URI in an OTP field,
            // the clock) or a transient store failure (busy database): not a
            // verification failure, so no quarantine. No detail is kept.
            Error::InvalidFormat(_) | Error::Store(_) => {
                PortError::Other("stored item could not be read".into())
            }
            // `ValidationError` names the field and a static reason only.
            Error::Validation(v) => PortError::Invalid(v.to_string()),
            Error::Conflict => PortError::Other("concurrent write, retry".into()),
            Error::WrongPassword => PortError::Other("wrong password or secret key".into()),
        }
    }
}

/// Vault access as the tools see it. `vault_id`s and references name
/// vaults by id: visibility and scope are checked by the caller.
pub trait VaultPort {
    /// Every vault of the account, MCP or not.
    fn vaults(&mut self) -> Result<Vec<VaultInfo>, PortError>;
    /// Every item of a vault, trashed ones included.
    fn items(&mut self, vault_id: Id) -> Result<Vec<Item>, PortError>;
    /// The value a reference points at.
    fn resolve(&mut self, r: &SecretRef) -> Result<Zeroizing<String>, PortError>;
    /// Stores a new version of an item (or its first one).
    fn save_item(&mut self, vault_id: Id, item: Item) -> Result<(), PortError>;
}

/// [`VaultPort`] over an unlocked repository.
pub struct RepoPort<'a, S: RecordStore>(pub &'a mut Repository<S>);

impl<S: RecordStore> RepoPort<'_, S> {
    fn vault(&self, vault_id: Id) -> Result<Vault, PortError> {
        self.0
            .vaults()?
            .into_iter()
            .find(|v| v.id == vault_id)
            .ok_or(PortError::NotFound)
    }
}

impl<S: RecordStore> VaultPort for RepoPort<'_, S> {
    fn vaults(&mut self) -> Result<Vec<VaultInfo>, PortError> {
        Ok(self
            .0
            .vaults()?
            .into_iter()
            .map(|v| VaultInfo {
                id: v.id,
                name: v.meta.name.clone(),
                mcp_access: v.meta.mcp_access,
            })
            .collect())
    }

    fn items(&mut self, vault_id: Id) -> Result<Vec<Item>, PortError> {
        let vault = self.vault(vault_id)?;
        Ok(self.0.items(&vault)?)
    }

    fn resolve(&mut self, r: &SecretRef) -> Result<Zeroizing<String>, PortError> {
        Ok(self.0.resolve(r)?)
    }

    fn save_item(&mut self, vault_id: Id, item: Item) -> Result<(), PortError> {
        let vault = self.vault(vault_id)?;
        Ok(self.0.save_item(&vault, item)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use onepass_core::{IntegrityError, ValidationError};

    #[test]
    fn core_errors_map_without_data() {
        assert_eq!(PortError::from(Error::NotFound), PortError::NotFound);
        for e in [Error::Integrity(IntegrityError::Aead), Error::Crypto] {
            assert_eq!(PortError::from(e), PortError::Integrity);
        }
        for e in [
            Error::InvalidFormat("hotp unsupported"),
            Error::Store("disk detail".into()),
        ] {
            assert_eq!(
                PortError::from(e),
                PortError::Other("stored item could not be read".into())
            );
        }
        let v = Error::Validation(ValidationError {
            field: "reference".into(),
            reason: "field is empty",
        });
        assert_eq!(
            PortError::from(v),
            PortError::Invalid("invalid reference: field is empty".into())
        );
        assert_eq!(
            PortError::from(Error::Conflict),
            PortError::Other("concurrent write, retry".into())
        );
    }
}
