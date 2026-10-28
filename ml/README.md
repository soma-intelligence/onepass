# onepass-ml

Outils Python du dataset d'autofill : ingestion, puis entrainement et export.

## Commandes

```sh
cd ml
uv sync                      # installe les versions epinglees (uv.lock)
uv run pytest                # tests
uv run python -m onepass_ml.ingest <src> <dst>
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
