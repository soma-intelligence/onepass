# Wi-Fi sur Windows et Linux

Les réseaux Wi-Fi du coffre arrivent tout seuls sur l'ordinateur, et les réseaux que l'ordinateur enregistre arrivent tout seuls dans le coffre. Il n'y a pas de bouton. Sur Mac, c'est l'app OnePass qui le fait ; ce document couvre Windows et Linux, où tout passe par la CLI `onepass`.

## Installer, une fois

```sh
onepass wifi install-agent
```

C'est tout. La commande installe un élément de connexion pour l'utilisateur courant, sans droits administrateur, et le démarre tout de suite :

- Linux : une unité systemd utilisateur, `~/.config/systemd/user/onepass-wifi.service`, activée avec `systemctl --user enable --now`. Elle démarre avec la session graphique.
- Windows : la valeur `OnePassWiFi` de la clé `Run` de l'utilisateur (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`). Une tâche planifiée « à l'ouverture de session » demande un administrateur ; la clé `Run` non.

Pour l'enlever : `onepass wifi uninstall-agent`.

## Ce qui se passe tout seul

L'agent lance `onepass wifi watch`, qui regarde le système et le coffre toutes les 15 secondes. Un tour sans nouveauté ne déverrouille rien.

- Un réseau ajouté ou modifié dans le coffre est écrit dans le système, en profil de l'utilisateur, rejoint automatiquement. Un réseau supprimé du coffre est retiré du système, seulement si c'est OnePass qui l'avait ajouté.
- Un réseau que l'ordinateur vient d'enregistrer (on a tapé le mot de passe une fois dans les réglages) entre dans le coffre comme élément Routeur, sans question. Au premier tour, les réseaux déjà enregistrés sur la machine entrent aussi.
- Un réseau supprimé du coffre ne revient pas par l'import : l'agent se souvient des profils déjà vus.

Les commandes à la main font la même chose en une fois :

- `onepass wifi sync` : écrit les réseaux du coffre dans le système. Relancée, elle ne change rien (idempotente).
- `onepass wifi import` : range les réseaux du système dans le coffre (`--vault` pour choisir le coffre, `--dry-run` pour voir sans écrire).

## Quels réseaux

Un élément Routeur part vers le système s'il a un SSID et un mot de passe WPA2 ou WPA3 personnel (8 à 63 caractères ASCII, ou 64 chiffres hexadécimaux). Ne partent jamais :

- les réseaux ouverts et les réseaux d'entreprise (802.1X) : rejoints automatiquement, ce sont des cibles faciles pour un faux point d'accès qui reprend le même nom ;
- le WEP, cassé ;
- les éléments à la corbeille ou archivés.

Si deux éléments ont le même SSID, le plus récemment modifié gagne. Les mêmes règles valent pour l'import : un réseau ouvert ou d'entreprise du système n'entre pas dans le coffre.

## Les demandes qui restent

- Le mot de passe OnePass, une fois par ouverture de session. Sans biométrie sur ces systèmes, l'agent ne peut pas lire le coffre sans lui. Sur Linux, il le demande dans une petite fenêtre (zenity ou kdialog) ; sur Windows, dans la fenêtre de console de l'agent. Si personne ne répond, l'agent tourne verrouillé : il note les nouveaux réseaux (leur nom seulement, la clé reste dans le système) et les range dans le coffre au prochain `onepass wifi sync`.
- Linux : polkit peut demander une fois le mot de passe système pour lire la clé d'un réseau qui n'appartient pas à l'utilisateur (réseau « système » créé par un autre compte ou à l'installation). Les réseaux que OnePass ajoute sont restreints à l'utilisateur (`connection.permissions`), ce que NetworkManager autorise sans question pour une session locale active sur les distributions courantes.
- Windows : aucune pour les profils de l'utilisateur.

## Sécurité

- Aucun mot de passe sur une ligne de commande (la liste des processus est lisible par les autres comptes). Sur Linux, tout passe par D-Bus. Sur Windows, le profil XML passe par un fichier créé pour l'appel dans `%TEMP%` de l'utilisateur (accessible à l'utilisateur, à SYSTEM et aux administrateurs seulement), écrasé puis supprimé juste après `netsh wlan add profile`.
- Aucun mot de passe affiché : les comptes rendus donnent des nombres et des codes.
- Le fichier d'état, `~/.config/onepass/wifi-state.json` (Linux) ou `%APPDATA%\onepass\wifi-state.json` (Windows), contient les SSID, les références système et une empreinte par réseau, jamais une clé. L'empreinte vient de l'élément (identifiant, SSID, sécurité, réseau masqué, date de modification), pas du mot de passe : une empreinte de mot de passe Wi-Fi se casse vite par force brute.
- Un réseau que le système avait avant OnePass (même SSID, profil qui n'est pas de OnePass) n'est jamais écrasé ni supprimé.

## Limites

- La CLI ne se compile pas encore pour Windows : la session (verrou, `/dev/tty`, signaux) et le stockage de la Secret Key sont propres à Unix. La partie Wi-Fi Windows est écrite et vérifiée à la compilation (`cargo check -p onepass-wifi --target x86_64-pc-windows-gnu`), mais ne tourne qu'une fois la CLI portée.
- Windows : `netsh` écrit dans la page de code OEM quand sa sortie part dans un tube. Les libellés sont reconnus en anglais et en français ; dans une autre langue, la lecture des clés échoue (comptée `password_unavailable`). Un nom de réseau hors ASCII peut revenir déformé à la lecture : l'import peut le mal nommer, et l'ajout reste exact (SSID écrit aussi en hexadécimal).
- Windows : lire la clé d'un profil « tous les utilisateurs » peut demander un administrateur selon la version ; sans lui, le réseau n'est pas importé.
- Linux : NetworkManager seulement (pas iwd seul, pas wpa_supplicant seul, pas ConnMan). Sans session graphique et sans terminal, l'agent tourne verrouillé.
- Un réseau déjà présent dans le système avant OnePass garde le mot de passe du système, même si le coffre en a un autre. Le supprimer une fois du système laisse OnePass le gérer.
- Un seul fichier d'état par utilisateur : deux comptes OnePass sur la même session (deux `--data-dir`) se partageraient la liste des réseaux appliqués.
- Le coffre ne bouge sur cet ordinateur que par la CLI (pas encore de synchronisation de fond) : un réseau ajouté sur un autre appareil arrive au prochain tour qui suit son arrivée dans le coffre local.
