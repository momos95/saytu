# Règles Opengrep

| Dossier | Origine | Licence | Embarqué dans l'image `worker` |
|---|---|---|---|
| `saytu/` | écrites pour SAYTU (24 règles : Java, JavaScript/TypeScript, Python, Go) | Apache-2.0 (licence du projet) | oui |
| `aikido/` | [AikidoSec/opengrep-rules](https://github.com/AikidoSec/opengrep-rules), commit `7ac79af` (2 règles GitHub Actions / npm) | MIT, `aikido/LICENSE` | oui |

Packs complémentaires **non embarqués**, à télécharger par chaque installation avec
`scripts/fetch-opengrep-rules.sh` (dans `data/rules/opengrep/`, lu par le worker en lecture seule) :

| Pack | Licence | Conséquence |
|---|---|---|
| `semgrep` — [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules) (~2 000 règles) | Semgrep Rules License v1.0 : usage **interne** uniquement, ni redistribution ni mise à disposition comme service | autorisé pour auditer le code de **votre** organisation ; interdit d'intégrer ces règles à une offre ou de les redistribuer |
| `trailofbits` — [trailofbits/semgrep-rules](https://github.com/trailofbits/semgrep-rules) | AGPL-3.0 | utilisable ; toute redistribution de ces règles se fait sous AGPL |

## Tester les règles SAYTU

Chaque fichier `<langage>.yaml` a un fichier d'exemples du même nom (`java.java`, `python.py`…)
annoté `ruleid:` (doit être détecté) et `ok:` (ne doit pas l'être) :

```
opengrep --test scanners/opengrep/rules/saytu
```
