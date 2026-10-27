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
| bridge.pv | `not (event(HostPaired(p_2,t_4,k_2)) && attacker(k_2))` | true | true |
| bridge.pv | `not (event(ExtConfirm(p_2,t_4,k_2)) && attacker(k_2))` | true | true |
| bridge.pv | `not (event(SessionKey(hon,r,s,k_2)) && attacker(k_2))` | true | true |
| bridge.pv | `not (event(AppMsg(hon,m)) && attacker(m))` | true | true |
| bridge.pv | `not (event(SessionKey(hon,r,s,k_2)) && attacker_p1(k_2))` | true | true |
| bridge.pv | `not (event(AppMsg(hon,m)) && attacker_p1(m))` | true | true |
| bridge.pv | `not (event(Record(p_2,k_2)) && attacker_p1(k_2))` | false | false |
| bridge.pv | `event(HostServe(hon,p_2,k_2,s,m)) ==> event(ExtFinish(hon,p_2,k_2,s))` | true | true |
| bridge.pv | `inj-event(ExtConfirm(p_2,t_4,k_2)) ==> inj-event(HostDone(p_2,t_4,k_2))` | true | true |
| bridge.pv | `inj-event(HostPaired(p_2,t_4,k_2)) ==> inj-event(ExtConfirm(p_2,t_4,k_2))` | true | true |
| bridge.pv | `inj-event(HostRecv(hon,s,d,n_8,m)) ==> inj-event(ExtSend(hon,s,d,n_8,m))` | true | true |
| bridge.pv | `inj-event(ExtRecv(hon,s,d,n_8,m)) ==> inj-event(HostSend(hon,s,d,n_8,m))` | true | true |
| bridge.pv | `not event(ExtConfirm(p_2,t_4,k_2))` | false | false |
| bridge.pv | `not event(HostPaired(p_2,t_4,k_2))` | false | false |
| bridge.pv | `not event(ExtFinish(hon,p_2,k_2,s))` | false | false |
| bridge.pv | `not event(HostRecv(hon,s,dir_e2h,ctr1,m))` | false | false |
| bridge.pv | `not event(ExtRecv(hon,s,dir_h2e,ctr1,m))` | false | false |
| bridge.pv | `not event(HostServe(cor,p_2,k_2,s,m))` | false | false |
| bridge_kem_mlkem_broken.pv | `not (event(HostPaired(p_2,t_4,k_2)) && attacker(k_2))` | true | true |
| bridge_kem_mlkem_broken.pv | `not (event(ExtConfirm(p_2,t_4,k_2)) && attacker(k_2))` | true | true |
| bridge_kem_mlkem_broken.pv | `not (event(SessionKey(hon,r,s,k_2)) && attacker(k_2))` | true | true |
| bridge_kem_mlkem_broken.pv | `not (event(AppMsg(hon,m)) && attacker(m))` | true | true |
| bridge_kem_mlkem_broken.pv | `not (event(SessionKey(hon,r,s,k_2)) && attacker_p1(k_2))` | true | true |
| bridge_kem_mlkem_broken.pv | `not (event(AppMsg(hon,m)) && attacker_p1(m))` | true | true |
| bridge_kem_mlkem_broken.pv | `not (event(Record(p_2,k_2)) && attacker_p1(k_2))` | false | false |
| bridge_kem_mlkem_broken.pv | `not event(HostPaired(p_2,t_4,k_2))` | false | false |
| bridge_kem_mlkem_broken.pv | `not event(ExtRecv(hon,s,dir_h2e,ctr1,m))` | false | false |
| bridge_kem_x25519_broken.pv | `not (event(HostPaired(p_2,t_4,k_2)) && attacker(k_2))` | true | true |
| bridge_kem_x25519_broken.pv | `not (event(ExtConfirm(p_2,t_4,k_2)) && attacker(k_2))` | true | true |
| bridge_kem_x25519_broken.pv | `not (event(SessionKey(hon,r,s,k_2)) && attacker(k_2))` | true | true |
| bridge_kem_x25519_broken.pv | `not (event(AppMsg(hon,m)) && attacker(m))` | true | true |
| bridge_kem_x25519_broken.pv | `not (event(SessionKey(hon,r,s,k_2)) && attacker_p1(k_2))` | true | true |
| bridge_kem_x25519_broken.pv | `not (event(AppMsg(hon,m)) && attacker_p1(m))` | true | true |
| bridge_kem_x25519_broken.pv | `not (event(Record(p_2,k_2)) && attacker_p1(k_2))` | false | false |
| bridge_kem_x25519_broken.pv | `not event(HostPaired(p_2,t_4,k_2))` | false | false |
| bridge_kem_x25519_broken.pv | `not event(ExtRecv(hon,s,dir_h2e,ctr1,m))` | false | false |
| emergency_kit.pv | `not (event(VaultCreated(acct_main,s,v_42,k_10)) && attacker(k_10))` | true | true |
| emergency_kit.pv | `not (event(ItemSealed(acct_main,m_14)) && attacker(m_14))` | true | true |
| emergency_kit.pv | `not (event(ItemSealed(restore_main,m_14)) && attacker(m_14))` | true | true |
| emergency_kit.pv | `event(VaultAccepted(restore_main,s,v_42,k_10)) ==> event(VaultCreated(acct_main,s,v_42,k_10))` | true | true |
| emergency_kit.pv | `event(ItemRead(restore_main,v_42,i,m_14)) ==> event(ItemSealed(acct_main,m_14)) \|\| event(ItemSealed(restore_main,m_14))` | true | true |
| emergency_kit.pv | `event(Pinned(restore_main,a,i)) ==> event(AccountOwned(acct_main,a,i))` | true | true |
| emergency_kit.pv | `Weak secret pw_main` | true | true |
| emergency_kit.pv | `not (event(ItemSealed(acct_kit_lost,m_14)) && attacker(m_14))` | true | true |
| emergency_kit.pv | `not (event(ItemSealed(restore_kit_lost,m_14)) && attacker(m_14))` | true | true |
| emergency_kit.pv | `not (event(AukCreated(acct_kit_lost,k_10)) && attacker(k_10))` | true | true |
| emergency_kit.pv | `event(Pinned(restore_kit_lost,a,i)) ==> event(AccountOwned(acct_kit_lost,a,i))` | true | true |
| emergency_kit.pv | `Weak secret pw_kit_lost` | false | false |
| emergency_kit.pv | `Weak secret pw_no_keyset` | true | true |
| emergency_kit.pv | `event(Pinned(restore_kit_pw,a,i)) ==> event(AccountOwned(acct_kit_pw,a,i))` | false | false |
| emergency_kit.pv | `event(ItemRead(restore_kit_pw,v_42,i,m_14)) ==> event(ItemSealed(acct_kit_pw,m_14)) \|\| event(ItemSealed(restore_kit_pw,m_14))` | false | false |
| emergency_kit.pv | `not event(Pinned(restore_main,a,i))` | false | false |
| emergency_kit.pv | `not event(VaultAccepted(restore_main,s,v_42,k_10))` | false | false |
| emergency_kit.pv | `not event(ItemRead(restore_main,v_42,i,m_14))` | false | false |
| emergency_kit.pv | `not event(ItemWritten(restore_main,v_42,m_14))` | false | false |
| emergency_kit.pv | `not event(Pinned(restore_kit_lost,a,i))` | false | false |
| emergency_kit.pv | `not event(AukDerived(restore_no_keyset))` | false | false |
| manifest.pv | `event(Accept(d_3,v_84,n,mh_12,e)) ==> event(Signed(v_84,n,p,mh_12,e))` | true | true |
| manifest.pv | `event(Accept(d_3,v_84,n,h1,e1))@i_6 && event(Accept(d_3,v_84,m_3,h2,e2))@j ==> i_6 > j \|\| m_3 ≥ n` | true | true |
| manifest.pv | `event(Accept(d_3,v_84,n,h1,e1)) && event(Accept(d_3,v_84,n,h2,e2)) ==> h1 = h2` | true | true |
| manifest.pv | `event(Fetched(d_3,v_84,seen(n,h0),n + 1,mh_12)) ==> event(Signed(v_84,n + 1,h0,mh_12,e))` | true | true |
| manifest.pv | `event(ItemAccepted(d_3,v_84,one_entry(i_6,ver_9,rh_6))) ==> event(Accept(d_3,v_84,n,mh_12,one_entry(i_6,ver_9,rh_6)))` | true | true |
| manifest.pv | `event(Fetched(d_3,v_84,seen(2,h0),4,mh_12)) ==> event(Signed(v_84,4,p,mh_12,e)) && event(Signed(v_84,3,h0,p,e3))` | false | false |
| manifest.pv | `event(Signed(v_84,2,p1,h1,e1)) && event(Signed(v_84,2,p2,h2,e2)) ==> h1 = h2` | false | false |
| manifest.pv | `not event(Fetched(d_3,v_84,seen(1,h0),2,mh_12))` | false | false |
| manifest.pv | `not event(Fetched(d_3,v_84,seen(1,h0),3,mh_12))` | false | false |
| manifest.pv | `not event(Fetched(d_3,v_84,seen(2,h0),2,mh_12))` | false | false |
| manifest.pv | `not event(Fetched(d_3,v_84,seen(2,h0),3,mh_12))` | false | false |
| manifest.pv | `not event(ItemAccepted(d_3,v_84,one_entry(i_6,ver_9,rh_6)))` | false | false |
| sanity.pv | `not attacker(secret_msg[])` | true | true |
| sanity.pv | `not attacker(auk_msg[])` | true | true |
| sanity.pv | `not attacker(bridge_msg[])` | true | true |
| sanity.pv | `not attacker(leaked_msg[])` | false | false |
| sanity.pv | `event(Received(m_4)) ==> event(Sent(m_4))` | true | true |
| sanity.pv | `not event(Received(m_4))` | false | false |
| sanity.pv | `not event(BridgeDone)` | false | false |
| sanity.pv | `Weak secret pw` | true | true |
| sanity.pv | `Weak secret pw_leaky` | false | false |
