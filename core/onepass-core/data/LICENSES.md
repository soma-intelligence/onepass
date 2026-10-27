# Word list sources and licenses

All lists hold one word per line, lowercase, NFC, without dice numbers.
Unit tests check 7776 unique entries per list, and that every word is
lowercase and NFC.

## eff_large_wordlist.txt

- Source: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
  (EFF long list for Diceware, 2016). Downloaded 2026-10-25, SHA-256 of the
  original file `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`.
- License: Creative Commons Attribution 3.0 United States (CC BY 3.0 US),
  https://creativecommons.org/licenses/by/3.0/us/
  Attribution: Electronic Frontier Foundation,
  https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
- Changes: the dice numbers were removed. Four entries contain a hyphen
  (drop-down, felt-tip, t-shirt, yo-yo) and are kept as published.

## fr_diceware_wordlist.txt

- Source: https://github.com/chmduquesne/diceware-fr/blob/master/tails/wordlist_fr_7776.txt
  (French list written by "Tango" for Tails OS and the Tor Project, hosted in
  the diceware-fr repository, folder `tails`, see its README.txt). Downloaded
  2026-10-25, SHA-256 of the original file
  `48014d49bbe0691fc82f0b6121f5e50db74b49501403571f80bd7b6e9fbbe022`.
- License: Creative Commons Zero v1.0 Universal (CC0 1.0, public domain
  dedication), https://creativecommons.org/publicdomain/zero/1.0/legalcode
  The list derives from Loren Brichter's `fr.txt`, also CC0.
- Changes: the dice numbers were removed. The upstream list holds both
  `internet` and `Internet`, which collapse to one entry once lowercased.
  `Internet` was replaced by `sable`, the first word of the curated
  8192-word extension (`wordlist_fr_8192.txt`, same author, same license,
  SHA-256 `76e13bdc4e8aabfb4d7fe1516a01f551dc7d17a3e85f3e5eeb8bbd18d9fc788a`)
  that is absent from the 7776 list.

## Lists rejected

- Matthieu Weber's French Diceware page (weber.fi.eu.org): the word list is
  Christophe-Marie Duquesne's, under CC BY 3.0, but the file holds about 340
  non-word entries (digits, symbols, years) and Weber's text carries no
  separate license for the data.
- Duquesne's `diceware-fr-5-jets.txt` (CC BY 3.0): same non-word entries.
- `ewd340/yafrdw`: derived from Lexique 3 (CC BY-SA 4.0), share-alike terms.
