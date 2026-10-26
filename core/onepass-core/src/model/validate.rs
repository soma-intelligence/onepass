use crate::error::{Error, Result, ValidationError};
use crate::model::field::FieldValue;
use crate::model::item::Item;

fn invalid(field: &str, reason: &'static str) -> Error {
    Error::Validation(ValidationError {
        field: field.to_owned(),
        reason,
    })
}

/// Checks an item and returns the first problem found: an empty title, then
/// each required field in template order that has no value. The error names
/// the field, never its content.
pub fn validate(item: &Item) -> Result<()> {
    if item.title.trim().is_empty() {
        return Err(invalid("title", "must not be empty"));
    }
    for field in item.sections.iter().flat_map(|s| s.fields.iter()) {
        if field.required && field.value == FieldValue::Empty {
            return Err(invalid(&field.id, "is required"));
        }
        // Hook for Task 10: per-field format checks (IBAN, BIP39, URL, ...)
        // go here, applied to non-empty values of the matching field.
    }
    Ok(())
}
