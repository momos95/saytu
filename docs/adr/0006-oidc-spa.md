# ADR-0006 — Authentification de l'interface : OIDC code + PKCE sans bibliothèque

**Statut** : accepté (phase 2)

## Contexte
L'interface Angular doit authentifier les utilisateurs auprès de Keycloak. L'URL de Keycloak est
connue au démarrage du conteneur (configuration runtime), pas à la compilation.

## Options
1. `keycloak-js` + `keycloak-angular` : complet, mais configuration statique au bootstrap, iframe
   de session, et deux dépendances à suivre au rythme des versions d'Angular et de Keycloak.
2. `angular-oauth2-oidc` : générique, plus large que le besoin.
3. **Implémentation ciblée** (`core/auth/oidc.ts`, ~250 lignes sans import Angular) — retenue.

## Décision
* Flux *authorization code* + PKCE S256, `state` et `nonce` aléatoires (32 octets), client public
  `africodeshield-web`.
* Jetons **en mémoire uniquement**. Seuls `state`, `nonce` et le vérificateur PKCE transitent par
  `sessionStorage` le temps de la redirection (10 min max). Un rechargement de page repasse par
  Keycloak, qui répond sans formulaire tant que sa session SSO est active.
* Validation de l'ID token : `iss`, `aud`, `azp`, `nonce`, `exp`. Sa signature n'est pas vérifiée
  dans le navigateur (OIDC Core §3.1.3.7 : jeton reçu directement du token endpoint en TLS). Les
  access tokens sont vérifiés par l'API (signature, émetteur, audience).
* Le jeton n'est ajouté qu'aux URL relatives sous `/api/v1` ; jamais à une URL absolue.
* URL de retour : chemins relatifs de l'application uniquement (pas de redirection ouverte).
* Rafraîchissement à la demande, mutualisé entre requêtes concurrentes ; échec ⇒ fin de session.
* Le module pur est testé dans Node, y compris avec le vecteur de test de l'annexe B du RFC 7636.

## Conséquences
+ Aucune dépendance supplémentaire, configuration runtime naturelle, code auditable.
− Pas de déconnexion par iframe de session : une déconnexion faite ailleurs est détectée au
  prochain rafraîchissement (≤ 5 min, durée de vie des access tokens).
