# Résultats du modèle formel (généré par formal/run.sh, ne pas modifier à la main)

| fichier | requête | attendu | obtenu | secondes |
| --- | --- | --- | --- | --- |
| sanity.pv | `not attacker(secret_msg[])` | true | true | 0.2 |
| sanity.pv | `not attacker(auk_msg[])` | true | true | 0.2 |
| sanity.pv | `not attacker(bridge_msg[])` | true | true | 0.2 |
| sanity.pv | `not attacker(leaked_msg[])` | false | false | 0.2 |
| sanity.pv | `event(Received(m_4)) ==> event(Sent(m_4))` | true | true | 0.2 |
| sanity.pv | `not event(Received(m_4))` | false | false | 0.2 |
| sanity.pv | `not event(BridgeDone)` | false | false | 0.2 |
| sanity.pv | `Weak secret pw` | true | true | 0.2 |
