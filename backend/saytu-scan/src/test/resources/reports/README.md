# Recorded scanner reports (test fixtures)

| File | Produced by |
|---|---|
| `opengrep-1.33.1.json` | Opengrep 1.33.1 on `../fixtures/vulnerable-app` with the SAYTU and Aikido rule packs (real run) |
| `trivy-misconfig-0.76.1.json` | Trivy 0.76.1 `fs --scanners misconfig` on `../fixtures/vulnerable-app` (real run, no vulnerability database) |
| `trivy-npm.json.golden`, `trivy-pom.json.golden` | Trivy v0.76.1 integration test golden files (`integration/testdata/`, Apache-2.0, © Aqua Security): real vulnerability reports, used because the Trivy database cannot be downloaded in every build environment |

Gitleaks reports are not stored: they contain the detected secrets. Gitleaks is tested against a
repository generated at test time, with secret-like values assembled in code.
