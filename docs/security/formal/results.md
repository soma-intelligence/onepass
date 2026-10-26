# Résultats du modèle formel (généré par formal/run.sh, ne pas modifier à la main)

| fichier | requête | attendu | obtenu |
| --- | --- | --- | --- |
| sanity.pv | `not attacker(secret_msg[])` | true | true |
| sanity.pv | `not attacker(auk_msg[])` | true | true |
| sanity.pv | `not attacker(bridge_msg[])` | true | true |
| sanity.pv | `not attacker(leaked_msg[])` | false | false |
| sanity.pv | `event(Received(m_4)) ==> event(Sent(m_4))` | true | true |
| sanity.pv | `not event(Received(m_4))` | false | false |
| sanity.pv | `not event(BridgeDone)` | false | false |
| sanity.pv | `Weak secret pw` | true | true |
| sanity.pv | `Weak secret pw_leaky` | false | false |
