//! Intent of a form, from an ordered rule table (spec 5.2): first match wins.

use serde::{Deserialize, Serialize};

use super::context::{ButtonClass, FieldRole, FormContext, FormKindHint};

/// Sealed in `model::usage::SiteUsage`: postcard encodes variants by index,
/// so new variants are only ever appended (pinned by `model::wire_tests`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    Login,
    Signup,
    Reset,
    Otp,
    Checkout,
    Address,
    Ignore,
}

/// Only visible fields count. A fillable field is one with a role.
pub fn intent_of(form: &FormContext) -> Intent {
    let roles: Vec<FieldRole> = form
        .fields
        .iter()
        .filter(|f| f.visible)
        .filter_map(|f| f.role)
        .collect();
    let count = |role: FieldRole| roles.iter().filter(|r| **r == role).count();

    // 1. Nothing to fill, or told to leave it alone.
    if form.intent_hints.ignore || roles.is_empty() {
        return Intent::Ignore;
    }
    // 2. Any card field.
    if roles.iter().any(|r| r.is_card()) {
        return Intent::Checkout;
    }
    let new_passwords = count(FieldRole::NewPassword);
    let current = count(FieldRole::CurrentPassword);
    // 3. Two new passwords, or current + new.
    if new_passwords >= 2 || (current >= 1 && new_passwords >= 1) {
        return Intent::Reset;
    }
    // 4. A new password: with a create button, a signup word or the
    // detector's signup kind, and also without any of them (an e-mail, a new
    // password and "Continue"). A new password is never a sign-in, so such a
    // form is never sent on its own.
    if new_passwords >= 1 {
        return Intent::Signup;
    }
    // 4 bis. No password and no code: an account being made all the same
    // (e-mail, name, "Create account" or a passkey button). The detector's
    // signup kind, or a create or passkey button with signup words, and
    // something of the identity to fill. Never sent on its own either.
    // When the detector read a sign-in step (kind login: an identifier with
    // a sign-in "Next" in a sign-in context), a create control and signup
    // wording are the page's side door ("No account? Create one!"), not
    // this form: an identifier-first sign-in stays a login.
    let secret = current >= 1 || roles.contains(&FieldRole::Otp);
    let creates = form
        .buttons
        .iter()
        .any(|b| matches!(b.class, ButtonClass::Create | ButtonClass::Passkey));
    let sign_in_step = form.intent_hints.kind == Some(FormKindHint::Login);
    let signup_hint = form.intent_hints.kind == Some(FormKindHint::Signup)
        || (!sign_in_step && creates && form.intent_hints.signup_words);
    let identity = roles
        .iter()
        .any(|r| r.is_identifier() || r.is_identity_or_address());
    if !secret && signup_hint && identity {
        return Intent::Signup;
    }
    // 5. A one-time code alone ("remember me" is not a fill target).
    let fillable: Vec<FieldRole> = roles
        .iter()
        .copied()
        .filter(|r| *r != FieldRole::RememberMe)
        .collect();
    if !fillable.is_empty() && fillable.iter().all(|r| *r == FieldRole::Otp) {
        return Intent::Otp;
    }
    // 6. A current password, or an identifier alone.
    if current >= 1 || roles.iter().any(|r| r.is_identifier()) {
        return Intent::Login;
    }
    // 7. Address or identity fields only.
    if roles.iter().any(|r| r.is_identity_or_address())
        && roles
            .iter()
            .all(|r| r.is_identity_or_address() || *r == FieldRole::RememberMe)
    {
        return Intent::Address;
    }
    Intent::Ignore
}

#[cfg(test)]
mod tests {
    use super::super::context::{ButtonContext, FieldContext, IntentHints, Prefilled};
    use super::*;

    fn form(roles: &[FieldRole]) -> FormContext {
        FormContext {
            form_ref: "f".into(),
            intent_hints: IntentHints {
                kind: None,
                signup_words: false,
                reset_words: false,
                checkout_words: false,
                ignore: false,
            },
            step_index: None,
            fields: roles
                .iter()
                .enumerate()
                .map(|(i, r)| FieldContext {
                    field_ref: format!("a{i}"),
                    role: Some(*r),
                    confidence: 0.9,
                    visible: true,
                    prefilled: Prefilled::Empty,
                })
                .collect(),
            buttons: vec![],
        }
    }

    #[test]
    fn ignore_hint_wins() {
        let mut f = form(&[FieldRole::CcNumber, FieldRole::CurrentPassword]);
        f.intent_hints.ignore = true;
        assert_eq!(intent_of(&f), Intent::Ignore);
    }

    #[test]
    fn no_fillable_role_is_ignore() {
        let mut f = form(&[FieldRole::Username]);
        f.fields[0].role = None;
        assert_eq!(intent_of(&f), Intent::Ignore);
        let mut f = form(&[FieldRole::Username]);
        f.fields[0].visible = false;
        assert_eq!(intent_of(&f), Intent::Ignore);
    }

    #[test]
    fn card_field_is_checkout() {
        let f = form(&[FieldRole::CurrentPassword, FieldRole::CcNumber]);
        assert_eq!(intent_of(&f), Intent::Checkout);
    }

    #[test]
    fn two_new_passwords_is_reset() {
        let f = form(&[FieldRole::NewPassword, FieldRole::NewPassword]);
        assert_eq!(intent_of(&f), Intent::Reset);
    }

    #[test]
    fn current_and_new_is_reset() {
        let f = form(&[FieldRole::CurrentPassword, FieldRole::NewPassword]);
        assert_eq!(intent_of(&f), Intent::Reset);
    }

    #[test]
    fn new_with_create_button_is_signup() {
        let mut f = form(&[FieldRole::Email, FieldRole::NewPassword]);
        f.buttons.push(ButtonContext {
            button_ref: "b".into(),
            class: ButtonClass::Create,
        });
        assert_eq!(intent_of(&f), Intent::Signup);
    }

    #[test]
    fn new_with_signup_words_is_signup() {
        let mut f = form(&[FieldRole::Email, FieldRole::NewPassword]);
        f.intent_hints.signup_words = true;
        assert_eq!(intent_of(&f), Intent::Signup);
    }

    #[test]
    fn new_with_signup_kind_hint_is_signup() {
        let mut f = form(&[FieldRole::Email, FieldRole::NewPassword]);
        f.intent_hints.kind = Some(super::super::context::FormKindHint::Signup);
        assert_eq!(intent_of(&f), Intent::Signup);
    }

    #[test]
    fn email_new_password_and_continue_is_signup_never_login() {
        // No signup word, no Create button: a plain "Continue".
        let mut f = form(&[FieldRole::Email, FieldRole::NewPassword]);
        f.buttons.push(ButtonContext {
            button_ref: "b".into(),
            class: ButtonClass::Next,
        });
        assert_eq!(intent_of(&f), Intent::Signup);
        let mut f = form(&[FieldRole::Username, FieldRole::NewPassword]);
        f.buttons.push(ButtonContext {
            button_ref: "b".into(),
            class: ButtonClass::Submit,
        });
        assert_eq!(intent_of(&f), Intent::Signup);
        // A new password alone too.
        assert_eq!(intent_of(&form(&[FieldRole::NewPassword])), Intent::Signup);
    }

    #[test]
    fn otp_alone_is_otp() {
        assert_eq!(intent_of(&form(&[FieldRole::Otp])), Intent::Otp);
    }

    #[test]
    fn current_password_is_login() {
        assert_eq!(
            intent_of(&form(&[FieldRole::CurrentPassword])),
            Intent::Login
        );
    }

    #[test]
    fn username_alone_is_login() {
        assert_eq!(intent_of(&form(&[FieldRole::Username])), Intent::Login);
        assert_eq!(intent_of(&form(&[FieldRole::Email])), Intent::Login);
    }

    #[test]
    fn identity_fields_only_is_address() {
        let f = form(&[FieldRole::GivenName, FieldRole::City, FieldRole::PostalCode]);
        assert_eq!(intent_of(&f), Intent::Address);
    }

    #[test]
    fn remember_me_alone_is_ignore() {
        assert_eq!(intent_of(&form(&[FieldRole::RememberMe])), Intent::Ignore);
    }

    #[test]
    fn identity_with_remember_me_is_address() {
        let f = form(&[FieldRole::GivenName, FieldRole::RememberMe]);
        assert_eq!(intent_of(&f), Intent::Address);
    }

    #[test]
    fn unknown_only_is_ignore() {
        assert_eq!(intent_of(&form(&[FieldRole::Unknown])), Intent::Ignore);
    }

    fn with_button(mut f: FormContext, class: ButtonClass) -> FormContext {
        f.buttons.push(ButtonContext {
            button_ref: format!("b{}", f.buttons.len()),
            class,
        });
        f
    }

    #[test]
    fn email_and_name_with_signup_kind_is_signup() {
        let mut f = form(&[FieldRole::Email, FieldRole::GivenName]);
        f.intent_hints.kind = Some(super::super::context::FormKindHint::Signup);
        assert_eq!(intent_of(&f), Intent::Signup);
    }

    #[test]
    fn create_button_and_signup_words_is_signup() {
        let mut f = with_button(form(&[FieldRole::Email]), ButtonClass::Create);
        f.intent_hints.signup_words = true;
        assert_eq!(intent_of(&f), Intent::Signup);
    }

    #[test]
    fn passkey_button_and_signup_words_is_signup() {
        let mut f = with_button(
            form(&[FieldRole::Email, FieldRole::FullName]),
            ButtonClass::Passkey,
        );
        f.intent_hints.signup_words = true;
        assert_eq!(intent_of(&f), Intent::Signup);
    }

    #[test]
    fn create_button_without_signup_words_stays_login() {
        // A sign-in form that also shows "Create account".
        let f = with_button(
            with_button(form(&[FieldRole::Email]), ButtonClass::Submit),
            ButtonClass::Create,
        );
        assert_eq!(intent_of(&f), Intent::Login);
    }

    #[test]
    fn login_with_create_link_and_password_stays_login() {
        let mut f = with_button(
            form(&[FieldRole::Username, FieldRole::CurrentPassword]),
            ButtonClass::Create,
        );
        f.intent_hints.signup_words = true;
        assert_eq!(intent_of(&f), Intent::Login);
    }

    #[test]
    fn identifier_first_sign_in_step_with_create_link_stays_login() {
        // login.live.com, spiegel.de (real-site bench 2026-11-02): the identifier alone, "Next",
        // and a "Create one!" or "Konto erstellen" control with signup wording on the page. The
        // detector read a sign-in step (kind login): the create control is a side door.
        let mut f = with_button(
            with_button(form(&[FieldRole::Username]), ButtonClass::Next),
            ButtonClass::Create,
        );
        f.intent_hints.kind = Some(super::super::context::FormKindHint::Login);
        f.intent_hints.signup_words = true;
        assert_eq!(intent_of(&f), Intent::Login);
        // The create control alone, the detector's kind still login.
        let mut f = with_button(form(&[FieldRole::Email]), ButtonClass::Create);
        f.intent_hints.kind = Some(super::super::context::FormKindHint::Login);
        f.intent_hints.signup_words = true;
        assert_eq!(intent_of(&f), Intent::Login);
        // Without the detector's kind, a create button and signup words still make a signup.
        let mut f = with_button(form(&[FieldRole::Email]), ButtonClass::Create);
        f.intent_hints.signup_words = true;
        assert_eq!(intent_of(&f), Intent::Signup);
    }

    #[test]
    fn signup_words_alone_on_identifier_stay_login() {
        let mut f = form(&[FieldRole::Email]);
        f.intent_hints.signup_words = true;
        assert_eq!(intent_of(&f), Intent::Login);
    }

    #[test]
    fn signup_kind_with_otp_is_not_a_passwordless_signup() {
        let mut f = form(&[FieldRole::Otp]);
        f.intent_hints.kind = Some(super::super::context::FormKindHint::Signup);
        assert_eq!(intent_of(&f), Intent::Otp);
    }
}
