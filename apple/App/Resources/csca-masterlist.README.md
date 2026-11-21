# csca-masterlist.ml

The CSCA master list the app checks passport chips against (passive authentication, ICAO 9303 part 11 and 12). It is the German Master List published by the BSI (Bundesamt für Sicherheit in der Informationstechnik), a CMS SignedData of type CscaMasterList signed by the German CSCA master list signer.

- Source page: https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.html
- Download: https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.zip?__blob=publicationFile&v=112 (GermanMasterList.zip, 521,335 bytes, SHA-256 a0d2b448d8a2ef383c66991897c970ab2f0494173d33ef0d55195127dae08a6a)
- File in the zip: DE_ML_2026-10-01-11-50-52.ml, copied here unchanged as csca-masterlist.ml
- Size: 934,771 bytes
- SHA-256: 2bc0f28b35d83f2fc2d1495b1c715add358dfb9ba343e9788bc27a19ced13a9f
- Published: 1 October 2026 (the page says 609 CSCA and CSCA link certificates from 119 countries or passport issuers)
- Downloaded: 21 November 2026

Terms of the BSI page: commercial use is allowed as long as the list is not used for advertising and its use does not suggest any cooperation with the BSI.

How the app trusts it: the list signer chains to a brainpoolP512r1 CSCA (csca-germany, ecdsa-with-SHA512), a curve the core's passive authentication does not support, so the strict `load_master_list` refuses it ("master list signer not issued by a listed CSCA"). The app loads it pinned instead (`load_master_list_pinned`, `FfiIcaoSession.newPinned`): the bytes must hash to the SHA-256 in `CSCAMasterList.swift`, next to this file, and the signer is not checked. The CSCAs on unsupported curves stay in the list and simply verify nothing.

Checks: `core/onepass-core/tests/scan_master_list_bsi.rs` checks the file against the pinned SHA-256, loads it pinned and looks for the FRA, USA and DEU CSCAs.

To rotate it: download the current zip from the source page, check its CMS signature (for example `openssl cms -verify -inform DER -noverify`), replace this file, then put its new SHA-256 in `CSCAMasterList.swift` (`sha256`) and in `SHIPPED_SHA256` of the core test, and update the size, hashes and dates above.
