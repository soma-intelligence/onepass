# Résultats du modèle formel (généré par formal/run.sh, ne pas modifier à la main)

| fichier | requête | attendu | obtenu |
| --- | --- | --- | --- |
| account.pv | `not (event(VaultCreated(acct_main,s,v_18,k_6)) && attacker(k_6))` | true | true |
| account.pv | `not (event(ItemSealed(acct_main,m_6)) && attacker(m_6))` | true | true |
| account.pv | `not (event(AukCreated(acct_sk_leaked,k_6)) && attacker(k_6))` | true | true |
| account.pv | `not (event(AukCreated(acct_pw_leaked,k_6)) && attacker(k_6))` | true | true |
| account.pv | `not (event(AukCreated(acct_main,k_6)) && attacker(k_6))` | true | true |
| account.pv | `Weak secret pw_main` | true | true |
| account.pv | `Weak secret pw_sk_leaked` | false | false |
| account.pv | `event(ParamsAccepted(i,a,sa,s,pm,px)) ==> event(ParamsSigned(i,a,sa,s,pm,px))` | true | true |
| account.pv | `event(VaultAccepted(t,s,v_18,k_6)) ==> event(VaultCreated(t,s,v_18,k_6))` | true | true |
| account.pv | `not event(Unlocked(acct_main))` | false | false |
| account.pv | `not event(Unlocked(acct_sk_leaked))` | false | false |
| account.pv | `not event(Unlocked(acct_pw_leaked))` | false | false |
| account.pv | `not event(VaultAccepted(acct_main,s,v_18,k_6))` | false | false |
| account.pv | `not event(ItemRead(acct_main,v_18,i,m_6))` | false | false |
| account.pv | `not event(ItemWritten(acct_main,v_18,m_6))` | false | false |
| account_kem_mlkem_broken.pv | `not (event(VaultCreated(acct_main,s,v_6,k_2)) && attacker(k_2))` | true | true |
| account_kem_mlkem_broken.pv | `not (event(ItemSealed(acct_main,m_2)) && attacker(m_2))` | true | true |
| account_kem_mlkem_broken.pv | `event(VaultAccepted(t,s,v_6,k_2)) ==> event(VaultCreated(t,s,v_6,k_2))` | true | true |
| account_kem_mlkem_broken.pv | `not event(Unlocked(acct_main))` | false | false |
| account_kem_mlkem_broken.pv | `not event(VaultAccepted(acct_main,s,v_6,k_2))` | false | false |
| account_kem_mlkem_broken.pv | `not event(ItemRead(acct_main,v_6,i,m_2))` | false | false |
| account_kem_mlkem_broken.pv | `not event(ItemWritten(acct_main,v_6,m_2))` | false | false |
| account_kem_x25519_broken.pv | `not (event(VaultCreated(acct_main,s,v_6,k_2)) && attacker(k_2))` | true | true |
| account_kem_x25519_broken.pv | `not (event(ItemSealed(acct_main,m_2)) && attacker(m_2))` | true | true |
| account_kem_x25519_broken.pv | `event(VaultAccepted(t,s,v_6,k_2)) ==> event(VaultCreated(t,s,v_6,k_2))` | true | true |
| account_kem_x25519_broken.pv | `not event(Unlocked(acct_main))` | false | false |
| account_kem_x25519_broken.pv | `not event(VaultAccepted(acct_main,s,v_6,k_2))` | false | false |
| account_kem_x25519_broken.pv | `not event(ItemRead(acct_main,v_6,i,m_2))` | false | false |
| account_kem_x25519_broken.pv | `not event(ItemWritten(acct_main,v_6,m_2))` | false | false |
| sanity.pv | `not attacker(secret_msg[])` | true | true |
| sanity.pv | `not attacker(auk_msg[])` | true | true |
| sanity.pv | `not attacker(bridge_msg[])` | true | true |
| sanity.pv | `not attacker(leaked_msg[])` | false | false |
| sanity.pv | `event(Received(m_4)) ==> event(Sent(m_4))` | true | true |
| sanity.pv | `not event(Received(m_4))` | false | false |
| sanity.pv | `not event(BridgeDone)` | false | false |
| sanity.pv | `Weak secret pw` | true | true |
| sanity.pv | `Weak secret pw_leaky` | false | false |
