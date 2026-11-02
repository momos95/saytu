# ADR-0003 — Isolation des scanners sans socket Docker

**Statut** : accepté (phase 1), implémentation en phase 4

## Contexte
Le code analysé est non fiable. Exigences : processus isolé, timeout, limites CPU/mémoire, espace
temporaire dédié, aucun token exposé, aucun script de build exécuté.

## Options
1. Un conteneur Docker par scanner, piloté par le socket Docker — monter `/var/run/docker.sock`
   équivaut à donner **root sur l'hôte** au service qui reçoit le code non fiable. Rejeté.
2. Runtime durci (gVisor, Kata, Firecracker) — excellent mais non disponible partout ; gardé comme
   option d'exploitation.
3. **Conteneur worker dédié + sous-processus bornés** — retenu.

## Décision
* Conteneur `worker` : utilisateur non root, `cap_drop: ALL`, `no-new-privileges`, système de
  fichiers racine en lecture seule, volume de travail dédié, limites `cpus`/`memory` Compose.
* Chaque scanner = sous-processus lancé depuis un `CommandSpec` validé :
  argv sans shell, exécutable absolu, environnement vide + liste blanche (refus des noms de type
  `TOKEN`, `SECRET`, `PASSWORD`, `ASKPASS`…), répertoire de travail 0700 hors des sources.
* Limites : `prlimit` (RLIMIT_CPU, RLIMIT_AS, RLIMIT_FSIZE, RLIMIT_NOFILE), `-Xmx` dérivé pour
  les outils JVM, timeout avec destruction de l'arbre de processus.
* Mode offline obligatoire : Trivy `--offline-scan --skip-db-update --skip-java-db-update`,
  Opengrep `--metrics=off` avec règles locales, Dependency-Check `--noupdate` et analyseurs
  distants désactivés (OSS Index, Node/Yarn/pnpm audit, Central, RetireJS update).
* Clone : token transmis au seul processus `git` via un askpass éphémère, hooks et sous-modules
  désactivés, clone superficiel ; aucun outil de build n'est jamais invoqué.
* Renforcement optionnel : `bwrap --unshare-net --ro-bind` lorsque les user namespaces sont
  disponibles (détection au démarrage, statut affiché dans l'UI).

## Conséquences
+ Pas de socket Docker, pas de privilège ; fonctionne sur tout hôte Linux avec Compose.
− Les processus d'un même job partagent le noyau et le réseau du worker : l'absence d'egress des
  scanners repose sur leur configuration offline (+ filtrage hôte recommandé, phase 8).
