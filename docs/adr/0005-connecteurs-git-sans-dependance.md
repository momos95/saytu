# ADR-0005 — Connecteurs Git dans un module sans dépendance (`acs-git`)

**Statut** : accepté (phase 2)

## Contexte
Les connecteurs manipulent les tokens en clair et envoient des requêtes vers des hôtes choisis par
un administrateur. C'est le code le plus exposé de la plateforme : fuite de token, SSRF, réponses
hostiles.

## Décision
* Module Maven `acs-git`, dépendant uniquement du JDK (`java.net.http`) et d'`acs-core`. Pas de
  Spring, pas de Jackson, pas de client HTTP tiers.
* Lecteur JSON minimal et strict (`JsonNode`, RFC 8259, profondeur bornée) : les réponses des forges
  sont lues, jamais sérialisées.
* Un seul point de sortie réseau, `GitHttpClient` :
  * politique de destination `EndpointPolicy` appliquée avant chaque requête (voir
    [docs/security.md](../security.md)) ;
  * redirections jamais suivies : un token n'est jamais rejoué vers un autre hôte ;
  * corps de réponse plafonné (8 Mo) ;
  * aucune journalisation ; erreurs typées dont les messages n'incluent jamais d'en-tête.
* Confiance TLS : magasin du JVM + autorité interne optionnelle (`ACS_GIT_CA_BUNDLE`). La
  vérification des certificats ne peut pas être désactivée (contrainte SQL `verify_tls` depuis V2).
* Règle ArchUnit : `com.africodeshield.git..` ne dépend d'aucun framework.

## Conséquences
+ Code critique compilable et testable avec le seul JDK, contre un vrai serveur HTTP local.
+ Surface de dépendances minimale sur le chemin des secrets.
− Lecteur JSON maison à maintenir (≈ 300 lignes, couvert par des tests de cas invalides).
