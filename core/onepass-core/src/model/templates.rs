use serde::{Deserialize, Serialize};

/// Kind of an item. Postcard encodes variants by index: new variants must
/// only ever be appended at the end (Task 9 adds the others after
/// `SecureNote`), never inserted or reordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemType {
    Login,
    SecureNote,
}
