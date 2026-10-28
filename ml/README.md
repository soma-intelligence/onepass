# onepass-ml

Outils Python du dataset d'autofill : ingestion, puis entrainement et export.

## Commandes

```sh
cd ml
uv sync                      # installe les versions epinglees (uv.lock)
uv run pytest                # tests (rapides, CPU)
uv run pytest -m slow        # taille reelle du modele B (< 30 Mo)
uv run python -m onepass_ml.ingest <src> <dst>
uv run python -m onepass_ml.train_encoder <data> out/encoder   # modele B
uv run python -m onepass_ml.eval out/encoder/encoder.onnx <data>
```

`<src>` : dossier du builder TypeScript (`extension/lab/out/dataset/<seed>-g<n>/`) avec
`part-*.jsonl.gz` et `manifest.json`. `<dst>` : recoit `train.parquet`, `val.parquet`,
`test.parquet`, `real_test.parquet` et `manifest.json` (comptes par split).

Exemple : `uv run python -m onepass_ml.ingest ../extension/lab/out/dataset/bench-g2 out/bench`

## Notes

- La cible d'entrainement est la colonne `target` ; `label` est le texte de l'etiquette (feature).
- `real_test.parquet` est ecrit meme sans lignes (schema complet), tant qu'il n'y a pas d'etiquettes a la main.
- Le seed, la version du generateur et `FEATURE_VERSION` sont dans les metadonnees Parquet.
- Lecture en flux par lots : la memoire reste stable meme avec 2 M de lignes.
- Modele B (`train_encoder`) : base `microsoft/Multilingual-MiniLM-L12-H384` (revision dans
  `BASE_REVISION`, cache Hugging Face local), vocabulaire elague aux pieces vues en train, 6 couches
  sur 12. `out/encoder/tokenizer.json` est la reference du tokenizer ; `onepass_ml/tokenizer.py`
  l'implemente sans dependance (a porter en TypeScript).
- Lightgbm et torch embarquent chacun un libomp : `tests/conftest.py` charge lightgbm d'abord et
  garde torch sur un fil, sinon pytest se bloque.
