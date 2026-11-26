import Foundation

/// The item's first one-time password secret (or `otpauth://` URI), across its sections in order.
/// Empty values (a template's blank TOTP field) are skipped. Nil when the item has none.
public func firstOtpValue(of item: FfiItem) -> String? {
    for section in item.sections {
        for field in section.fields {
            if case .otp(let value) = field.value,
                !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            {
                return value
            }
        }
    }
    return nil
}

/// The item's first password field with a value, across its sections in order (a Login's main
/// password before a custom one). Nil when the item has none: the "Copier le mot de passe" command
/// is then disabled.
public func firstPasswordField(of item: FfiItem) -> FfiField? {
    for section in item.sections {
        for field in section.fields {
            if case .password(let value) = field.value, !value.isEmpty { return field }
        }
    }
    return nil
}
