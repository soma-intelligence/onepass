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
| emergency_kit.pv | `not event(ItemWritten(restore_kit_lost,v_42,m_14))` | false | false |
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
| rotation.pv | `not (event(ItemSealedNew(d,m)) && attacker(m))` | true | true |
| rotation.pv | `not (event(Rotated(s,ip_4,r,ro,k_13,ik)) && attacker(k_13))` | true | true |
| rotation.pv | `not (event(Rotated(s,ip_4,r,ro,k_13,ik)) && attacker(ik))` | true | true |
| rotation.pv | `event(Adopt(d,s,ip_4)) ==> event(Rotated(s,ip_4,r,ro,k_13,ik))` | true | true |
| rotation.pv | `not event(Adopt(devA,devB,ip_4))` | true | true |
| rotation.pv | `not event(Adopt(devC,devB,ip_4))` | true | true |
| rotation.pv | `event(VaultAcceptedNew(d,ip_4,v_42,k_13)) ==> event(VaultCreatedNew(ip_4,v_42,k_13))` | true | true |
| rotation.pv | `event(PinRoster(restore_new,ip_4,ro)) ==> event(Rotated(s,ip_4,r,ro,k_13,ik))` | true | true |
| rotation.pv | `event(PinRoster(restore_old,ip_4,ro)) ==> event(Rotated(s,ip_4,r,ro,k_13,ik))` | false | false |
| rotation.pv | `not event(Adopt(devC,devA,ip_4))` | false | false |
| rotation.pv | `not event(Adopt(devA,devC,ip_4))` | false | false |
| rotation.pv | `not event(VaultAcceptedNew(devC,ip_4,v_42,k_13))` | false | false |
| rotation.pv | `not event(ItemSealedNew(devC,m))` | false | false |
| rotation.pv | `not event(PinRoster(restore_new,ip_4,ro))` | false | false |
| rotation_account_anchor.pv | `event(Adopt(d,s,ip_1)) ==> event(Rotated(s,ip_1,r,ro,k_5,ik))` | false | false |
| rotation_account_anchor.pv | `not (event(ItemSealedNew(d,m)) && attacker(m))` | false | false |
| rotation_account_anchor.pv | `not event(Adopt(devC,devA,ip_1))` | false | false |
| rotation_autofollow.pv | `event(Adopt(d,s,ip_1)) ==> event(Rotated(s,ip_1,r,ro,k_5,ik))` | false | false |
| rotation_autofollow.pv | `not event(Adopt(devC,devB,ip_1))` | false | false |
| rotation_autofollow.pv | `not (event(ItemSealedNew(d,m)) && attacker(m))` | false | false |
| rotation_autofollow.pv | `not event(Adopt(devC,devA,ip_1))` | false | false |
| remote_unlock.pv | `not attacker(auk[])` | true | true |
| remote_unlock.pv | `event(AgentOnly(m_29,p,r,d_8)) ==> event(PhoneAnswered(m_29,p,r,d_8))` | true | true |
| remote_unlock.pv | `inj-event(AgentOnly(m_29,p,r,d_8)) ==> inj-event(PhoneAnswered(m_29,p,r,d_8))` | true | true |
| remote_unlock.pv | `not event(PhoneEnrolled(m_29,k_11))` | false | false |
| remote_unlock.pv | `not event(PhoneEnrolled(mac2_id,k_11))` | false | false |
| remote_unlock.pv | `not event(PhoneAnswered(mac2_id,p,r,dec_once))` | false | false |
| remote_unlock.pv | `not event(AgentOnly(m_29,p,r,dec_once))` | false | false |
| remote_unlock.pv | `not event(AgentOnly(m_29,p,r,dec_grant5m))` | false | false |
| remote_unlock_lookup_broken.pv | `not attacker(auk[])` | false | false |
| remote_unlock_lookup_broken.pv | `not event(AgentOnly(m_29,p,r,dec_once))` | false | false |
| remote_unlock_sig_broken.pv | `not attacker(auk[])` | true | true |
| remote_unlock_sig_broken.pv | `event(AgentOnly(m_29,p,r,d_8)) ==> event(PhoneAnswered(m_29,p,r,d_8))` | false | false |
| remote_unlock_sig_broken.pv | `event(AgentOnly(m_29,p,r,d_8)) ==> event(PhoneAnswered(m_29,p,r,d2))` | true | true |
| remote_unlock_sig_broken.pv | `not event(AgentOnly(m_29,p,r,dec_once))` | false | false |
| sanity.pv | `not attacker(secret_msg[])` | true | true |
| sanity.pv | `not attacker(auk_msg[])` | true | true |
| sanity.pv | `not attacker(bridge_msg[])` | true | true |
| sanity.pv | `not attacker(leaked_msg[])` | false | false |
| sanity.pv | `event(Received(m_4)) ==> event(Sent(m_4))` | true | true |
| sanity.pv | `not event(Received(m_4))` | false | false |
| sanity.pv | `not event(BridgeDone)` | false | false |
| sanity.pv | `Weak secret pw` | true | true |
| sanity.pv | `Weak secret pw_leaky` | false | false |
| sharing.pv | `not (event(ItemSealedAfterRemoval(m_14)) && attacker_p1(m_14))` | true | true |
| sharing.pv | `not (event(GenerationCreated(v_18,g1,k_9)) && attacker(k_9))` | true | true |
| sharing.pv | `not (event(GenerationCreated(v_18,g2,k_9)) && attacker_p1(k_9))` | true | true |
| sharing.pv | `event(ManifestAccepted(d,v_18,w_8,g_19)) ==> event(MemberRole(v_18,w_8,role_write,g_19))` | true | true |
| sharing.pv | `event(MembershipAccepted(d,v_18,n)) ==> event(MembershipSigned(v_18,n,mgr_2)) && event(Manager(v_18,mgr_2))` | true | true |
| sharing.pv | `event(EnvelopeAccepted(d,v_18,g_19,k_9)) ==> event(GenerationCreated(v_18,g_19,k_9))` | true | true |
| sharing.pv | `event(MemberAdded(v_18,m_14,r_3,lvl_link)) ==> r_3 = role_read` | true | true |
| sharing.pv | `not event(EnvelopeAccepted(bob,vlt,g1,k_9))` | false | false |
| sharing.pv | `not event(ManifestAccepted(carol,v_18,bob,g1))` | false | false |
| sharing.pv | `not event(EnvelopeAccepted(bob,vlt,g2,k_9))` | false | false |
| sharing.pv | `not event(ItemRead(bob,vlt,g2,m_14))` | false | false |
| sharing.pv | `not event(ItemSealed(bob,g2,m_14))` | false | false |
| sharing.pv | `not (event(GenerationCreated(v_18,g1,k_9)) && attacker_p1(k_9))` | false | false |
| sharing_member_autofollow.pv | `not event(AdoptIdentity(bob_side,acct,pk(idk_x[])))` | false | false |
| sharing_member_autofollow.pv | `not (event(EnvelopeSealed(d,ip_1,k_5)) && attacker(k_5))` | false | false |
| sharing_member_autofollow.pv | `not event(AdoptFrom(bob_side,devA,ip_1))` | false | false |
| sharing_member_rotation.pv | `not event(AdoptIdentity(bob_side,acct,pk(idk_x[])))` | true | true |
| sharing_member_rotation.pv | `event(AdoptIdentity(d,a_1,ip_2)) ==> event(Rotated(s,ip_2,r,ro,k_11,ik))` | true | true |
| sharing_member_rotation.pv | `not event(AdoptFrom(bob_side,devB,ip_2))` | true | true |
| sharing_member_rotation.pv | `not (event(EnvelopeSealed(d,ip_2,k_11)) && attacker(k_11))` | true | true |
| sharing_member_rotation.pv | `not event(Confirmed(bob_side,role_read,ip_2))` | false | false |
| sharing_member_rotation.pv | `not event(Confirmed(bob_side,role_write,ip_2))` | false | false |
| sharing_member_rotation.pv | `not event(AdoptFrom(bob_side,devA,ip_2))` | false | false |
| sharing_no_rekey.pv | `not (event(ItemSealedAfterRemoval(m_10)) && attacker_p1(m_10))` | false | false |
| sharing_no_rekey.pv | `not event(MembershipAccepted(bob,vlt,(nxt(seq1),hb_2)))` | false | false |
| sharing_no_rekey.pv | `not (event(ItemSealed(bob,g1,m_10)) && event(ItemSealedAfterRemoval(m_10)))` | false | false |
| sharing_server_directory.pv | `not (event(GenerationCreated(v_6,g1,k_2)) && attacker(k_2))` | false | false |
| sharing_server_directory.pv | `not (event(ItemSealedAfterRemoval(m_7)) && attacker_p1(m_7))` | false | false |
| sharing_server_directory.pv | `not event(GenerationCreated(v_6,g1,k_2))` | false | false |
