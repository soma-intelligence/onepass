public enum FillStep: Equatable, Sendable {
    case value(FieldKind)
    case tab
    /// Reserved: the helper uses it in place of `.tab` once it knows the password element.
    case focusPassword
}

public enum FillFlow {
    public static func steps(
        focused: FieldKind, hasPasswordBelow: Bool, hasTotp: Bool
    ) -> [FillStep] {
        var steps: [FillStep]
        switch focused {
        case .username:
            steps = hasPasswordBelow
                ? [.value(.username), .tab, .value(.password)] : [.value(.username)]
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
