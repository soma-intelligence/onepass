//! Site-aware password generation: the constraint engine shared by the
//! `passwordrules` reader, hint parsing and the generator profiles.

mod constraints;
mod hints;
mod passwordrules;
mod profile;
mod resolve;

pub use constraints::{CharSet, Constraints, draw};
pub use hints::parse_hints;
pub use passwordrules::parse_passwordrules;
pub use profile::{GenerationReport, Profile, generate_for};
pub use resolve::{PasswordContext, Source};
