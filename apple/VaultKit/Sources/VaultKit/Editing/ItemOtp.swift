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
