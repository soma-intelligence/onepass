//! Site catalogs: 2FA and passkey support, breached sites (spec 3.4).

/// Sites offering 2FA or passkeys.
#[derive(Debug, Default, Clone)]
pub struct SiteDirectory {}

/// Verified breaches by domain.
#[derive(Debug, Default, Clone)]
pub struct BreachCatalog {}
