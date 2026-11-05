# Recorded scanner reports (test fixtures)

| File | Produced by |
|---|---|
| `opengrep-1.33.1.json` | Opengrep 1.33.1 on `../fixtures/vulnerable-app` with the SAYTU and Aikido rule packs (real run) |
| `trivy-misconfig-0.76.1.json` | Trivy 0.76.1 `fs --scanners misconfig` on `../fixtures/vulnerable-app` (real run, no vulnerability database) |
| `phpcs-4.0.2.json` | PHP_CodeSniffer 4.0.2, standard PSR12, on `../fixtures/quality-app/php` (real run) |
| `cppcheck-2.13.0.xml` | Cppcheck 2.13.0 (the Ubuntu 24.04 version) on `../fixtures/quality-app/c` (real run) |
| `sqlfluff-4.4.0.json` | SQLFluff 4.4.0 on `../fixtures/quality-app/sql` — real run from the sources, with the `regex` dependency replaced by Python's `re` (PyPI unreachable in the development environment) |
| `checkstyle-format.xml`, `pmd-format.json`, `eslint-format.json` | **written by hand** following the report writers of Checkstyle 14.3.0 (`XMLLogger`), PMD 7.28.0 (`JsonRenderer`, test files `expected*.json`) and ESLint 9.39.5 (`json` formatter), because those tools could not be downloaded in the development environment. The real tools run on generated repositories in `QualityToolsTest` during the worker image build |
| `trivy-npm.json.golden`, `trivy-pom.json.golden` | Trivy v0.76.1 integration test golden files (`integration/testdata/`, Apache-2.0, © Aqua Security): real vulnerability reports, used because the Trivy database cannot be downloaded in every build environment |

Gitleaks reports are not stored: they contain the detected secrets. Gitleaks is tested against a
repository generated at test time, with secret-like values assembled in code.
