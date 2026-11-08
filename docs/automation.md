# Planification, alertes, comparaison, utilisateurs et IA locale (phase 7)

Tout se règle dans **Utilisateurs & paramètres** (onglets Planification, Alertes, Utilisateurs, IA locale) ;
les modifications sont réservées au rôle ADMIN et tracées dans le journal d'audit.

## Audits planifiés

* Expression cron à 5 champs (`0 2 * * 1-5` = 2 h du lundi au vendredi), à 6 champs (format Spring,
  secondes en tête) ou macro (`@daily`, `@weekly`) ; fuseau horaire IANA (`Europe/Paris`).
* Périmètre : tous les dépôts sélectionnés pour l'audit (y compris ceux ajoutés après coup) ou une liste
  de dépôts. L'API accepte aussi une liste d'organisations (`scope: NAMESPACES`), résolue à chaque
  déclenchement.
* Le worker vérifie toutes les 30 s les planifications échues. Un déclenchement crée un audit ordinaire
  (déclencheur `SCHEDULED`, visible dans la page Audits). Il est **ignoré, avec sa raison**, si l'audit
  précédent de la même planification n'est pas terminé, ou si aucun dépôt visé n'est sélectionné.
* Intervalle minimal : 15 minutes. Une planification désactivée ne se déclenche pas.
* Non implémenté : « ignorer les branches inchangées » (demande une lecture distante avant clonage) ;
  le doublon d'un job déjà en file reste évité par le planificateur.

API : `GET|POST /api/v1/schedules`, `PUT|DELETE /api/v1/schedules/{id}`.

## Alertes (webhooks)

* Événements : `NEW_FINDINGS` (vulnérabilités **créées** par le job, encore ouvertes, au-dessus de la
  gravité minimale — critique par défaut) et `SCAN_COMPLETED` (fin de chaque audit de branche).
* Formats : JSON générique, ou `{"text": "…"}` compris par Slack, Mattermost et Rocket.Chat.
* Boîte d'envoi (`webhook_delivery`) écrite juste après l'enregistrement des résultats du job (une erreur d'alerte ne peut jamais annuler les résultats), envoyée par le
  worker : 6 essais au plus (1 min, 5 min, 30 min, 2 h, 6 h), statut et dernière erreur visibles dans
  « Envois ». Bouton « Tester » : envoi immédiat d'un message de test.
* Contenu : dépôt, branche, commit, liens vers SAYTU, et pour chaque vulnérabilité (20 au plus) sa
  gravité, son titre, sa règle et son emplacement. **Jamais** de code, de preuve ni de secret.
* L'URL n'est jamais réaffichée en clair (beaucoup de services y mettent leur jeton) : seul l'hôte est
  montré ; la modifier demande de la ressaisir.
* Les envois passent par le proxy Java du worker (`SAYTU_JAVA_PROXY_OPTS`) s'il est défini.

### Vérifier la signature

Avec un secret, chaque requête porte `X-Saytu-Timestamp` (secondes) et
`X-Saytu-Signature: sha256=<hex>` = HMAC-SHA256(secret, `<timestamp>.<corps brut>`). Côté récepteur :

```python
import hmac, hashlib, time
def valid(secret: bytes, timestamp: str, body: bytes, signature: str) -> bool:
    if abs(time.time() - int(timestamp)) > 300:          # rejeu
        return False
    expected = "sha256=" + hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```

Exemple de corps `NEW_FINDINGS` (format générique) :

```json
{"event": "NEW_FINDINGS", "source": "SAYTU", "repository": "acme/api", "branch": "main", "commitSha": "70df3256…",
 "jobId": "…", "runId": "…", "url": "https://saytu.example/repositories/…", "minSeverity": "HIGH",
 "counts": {"CRITICAL": 1, "HIGH": 2}, "total": 3, "truncated": false,
 "findings": [{"id": "…", "severity": "CRITICAL", "type": "SECRET", "scanner": "gitleaks", "ruleId": "aws-access-token",
               "title": "AWS access token", "location": "config/app.env:3", "cve": null, "package": null,
               "url": "https://saytu.example/findings/…"}]}
```

Les liens utilisent `SAYTU_PUBLIC_URL`.

## Comparaison de deux analyses

Page **Détail dépôt** → « Derniers audits du dépôt » → « comparer » : différence avec l'analyse terminée
précédente de la même branche (`GET /api/v1/jobs/{jobId}/compare`, paramètre `with` pour choisir l'autre
analyse, y compris d'une autre branche du même dépôt).

* **Introduites** : vues dans la nouvelle analyse et pas dans l'ancienne, alors que les outils qui les
  signalent avaient réussi dans l'ancienne.
* **Corrigées** : vues dans l'ancienne, absentes de la nouvelle, alors que tous les outils qui les
  signalaient ont réussi dans la nouvelle.
* **Non vérifiables** : tous les autres écarts — un outil en échec ou non exécuté ne prouve jamais
  l'absence d'un problème.
* Avec, pour chaque outil, son statut et sa version des deux côtés, et le score de chaque analyse.

## Utilisateurs

La page s'appuie sur l'API d'administration de Keycloak, via un client confidentiel dédié
`saytu-admin-api` dont le compte de service n'a que `view-users`, `query-users` et `manage-users` **du
royaume saytu** (aucun droit sur le royaume master ni sur la configuration).

Mise en place, une fois, pile démarrée :

```powershell
powershell -ExecutionPolicy Bypass -File scripts\keycloak-admin-client.ps1     # Windows
```
```bash
bash scripts/keycloak-admin-client.sh                                          # Linux / macOS
```
puis `docker compose up -d api`. Le script utilise le compte d'administration initial de Keycloak
(`KC_BOOTSTRAP_ADMIN_*` du `.env`), crée ou met à jour le client et écrit
`SAYTU_KEYCLOAK_ADMIN_CLIENT_SECRET` dans `.env`. Sans lui, la page l'indique et la console Keycloak reste
utilisable.

* Un rôle SAYTU par utilisateur : VIEWER (lecture), AUDITOR (audits, triage, IA), ADMIN (tout).
* Création : SAYTU génère un **mot de passe temporaire**, affiché une seule fois, à changer à la première
  connexion. Même principe pour « Nouveau mot de passe ». SAYTU ne stocke aucun mot de passe.
* Un administrateur ne peut ni retirer son propre rôle ADMIN ni désactiver son propre compte.

## IA locale (Ollama, optionnelle)

1. `docker compose --profile ai up -d` (service `ollama`, réseau interne uniquement, aucun port publié).
2. `docker compose exec ollama ollama pull qwen2.5-coder:7b` (≈ 4,7 Go ; environ 8 Go de mémoire à l'usage).
   Sur une installation isolée : copier le dossier de modèles d'une machine connectée dans le volume `ollama`.
3. Onglet **IA locale** : cocher « activée », « Tester la connexion », enregistrer.

Le détail d'une vulnérabilité propose alors « Expliquer avec l'IA locale » (AUDITOR, ADMIN) : explication,
impact, étapes, exemple et tests, en plus de la correction proposée déterministe. Ce qui est envoyé au
modèle : titre, règle, CWE/CVE, emplacement, description, extrait déjà masqué et étapes déterministes —
**pas le code du dépôt**, qui n'est pas conservé après l'audit. Le texte du résultat peut avoir été écrit
dans le dépôt audité : la consigne demande au modèle de le traiter comme une donnée ; la réponse est
affichée comme du texte, jamais exécutée ni appliquée. Les explications sont gardées
(`finding_remediation`) et peuvent être régénérées.

Licences : Ollama MIT ; qwen2.5-coder 7B Apache-2.0. Vérifiez la licence de tout autre modèle (certains,
comme Llama, ont des conditions d'usage propres).
