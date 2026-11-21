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

Checks: `core/onepass-core/tests/scan_master_list_bsi.rs` loads this file with `load_master_list` and looks for the FRA and USA CSCAs. That test is ignored for now: the list signer chains to a brainpoolP512r1 CSCA (csca-germany, ecdsa-with-SHA512), a curve the core's passive authentication does not support yet, so loading fails with "master list signer not issued by a listed CSCA".

To update it, download the current zip from the source page, check its CMS signature, replace this file and update the size, hashes and dates above.
