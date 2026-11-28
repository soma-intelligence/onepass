public enum FillStep: Equatable, Sendable {
    case value(FieldKind)
    case tab
    /// In place of `.tab` when the helper knows the password element: focus it by Accessibility.
    case focusPassword
}

public enum FillFlow {
    /// `passwordKnown`: the helper holds the password field's element, so it moves the focus
    /// there (`.focusPassword`) instead of pressing Tab and hoping the next field is the password.
    public static func steps(
        focused: FieldKind, hasPasswordBelow: Bool, hasTotp: Bool, passwordKnown: Bool = false
    ) -> [FillStep] {
        var steps: [FillStep]
        switch focused {
        case .username:
            steps = hasPasswordBelow
                ? [.value(.username), passwordKnown ? .focusPassword : .tab, .value(.password)]
                : [.value(.username)]
        case .password:
            steps = [.value(.password)]
        case .oneTimeCode:
            return [.value(.oneTimeCode)]
        case .other:
            return []
        }
        if hasTotp { steps.append(.value(.oneTimeCode)) }
        return steps
    }
}
