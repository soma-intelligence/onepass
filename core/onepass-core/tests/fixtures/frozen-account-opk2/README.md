# Compte figé OPK2

Compte synthétique (mot de passe et Secret Key de test, aucune donnée réelle) aux paramètres KDF de développement (`m_kib = 8192, t = 1, p = 1`), au format de l'époque `OPK2` : paramètres `OPP2` à l'époque 1 et keyset `OPK2` sans clé KEM retirée. Produit une seule fois le 2026-10-30, avant l'introduction de `OPK3`, par `Account::create_with_params` du commit 11928c76. Ne jamais le régénérer : `opk2_still_opens` (`tests/frozen_account.rs`) vérifie qu'un compte `OPK2` déjà stocké s'ouvre toujours, avec `retired_kem` vide.
