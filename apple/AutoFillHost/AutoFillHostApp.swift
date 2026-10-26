import SwiftUI
import UIKit

/// Test host for the AutoFill UI test (ruling A16): a sign-in form whose fields carry the content
/// types AutoFill looks for. iOS only, never embedded in OnePass, never shipped. UIKit text fields
/// rather than SwiftUI ones, so the content types reach AutoFill exactly as an ordinary app sets them.
@main
struct AutoFillHostApp: App {
    var body: some Scene {
        WindowGroup {
            SignInForm()
                .ignoresSafeArea(.keyboard)
        }
    }
}

private struct SignInForm: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> SignInViewController {
        SignInViewController()
    }

    func updateUIViewController(_ controller: SignInViewController, context: Context) {}
}

final class SignInViewController: UIViewController {
    private let username = UITextField()
    private let password = UITextField()
    private let code = UITextField()
    private let status = UILabel()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground

        let title = UILabel()
        title.text = "Connexion"
        title.font = .preferredFont(forTextStyle: .largeTitle)

        configure(username, placeholder: "Identifiant", identifier: "host.username")
        username.textContentType = .username
        username.keyboardType = .emailAddress

        configure(password, placeholder: "Mot de passe", identifier: "host.password")
        password.textContentType = .password
        password.isSecureTextEntry = true

        configure(code, placeholder: "Code à usage unique", identifier: "host.code")
        code.textContentType = .oneTimeCode
        code.keyboardType = .numberPad

        let signIn = UIButton(configuration: .borderedProminent())
        signIn.setTitle("Se connecter", for: .normal)
        signIn.accessibilityIdentifier = "host.signIn"
        signIn.addAction(UIAction { [weak self] _ in self?.signIn() }, for: .primaryActionTriggered)

        // What the form received, without the password itself (its length only).
        status.accessibilityIdentifier = "host.status"
        status.numberOfLines = 0
        status.font = .preferredFont(forTextStyle: .footnote)

        let stack = UIStackView(arrangedSubviews: [title, username, password, code, signIn, status])
        stack.axis = .vertical
        stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 32),
            stack.leadingAnchor.constraint(equalTo: view.layoutMarginsGuide.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: view.layoutMarginsGuide.trailingAnchor),
        ])
    }

    private func configure(_ field: UITextField, placeholder: String, identifier: String) {
        field.placeholder = placeholder
        field.accessibilityIdentifier = identifier
        field.borderStyle = .roundedRect
        field.autocapitalizationType = .none
        field.autocorrectionType = .no
    }

    private func signIn() {
        view.endEditing(true)
        let user = username.text ?? ""
        let length = password.text?.count ?? 0
        let otp = code.text ?? ""
        status.text = "Identifiant : \(user) ; mot de passe : \(length) caractères ; code : \(otp)"
    }
}
