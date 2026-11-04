# Connexions Git — guide administrateur

Page **Connexions Git** (rôle ADMIN pour créer, modifier, tester et supprimer ; lecture pour tous).
Utilisez toujours un token **en lecture seule** dédié à AfriCodeShield.

| Plateforme | URL | Identifiant | Token et droits |
|---|---|---|---|
| GitLab.com | vide | — | Personal, group ou project access token : `read_api` + `read_repository` |
| GitLab Self-Managed | `https://gitlab.example.org` (sous-chemin accepté) | — | idem ; vérification des scopes à partir de GitLab 15.5 |
| GitHub.com | vide | — | Fine-grained : *Contents: read* + *Metadata: read*. Classique : `repo` (+ `read:org`) |
| GitHub Enterprise Server | `https://github.example.org` (API déduite : `/api/v3`) | — | idem |
| Bitbucket Cloud | vide (`https://bitbucket.org`) | e-mail du compte Atlassian | API token : `read:user`, `read:workspace`, `read:repository` |
| Bitbucket Cloud (access token) | vide | — (laisser vide) | Access token de workspace, projet ou dépôt, en lecture |
| Bitbucket Data Center | `https://bitbucket.example.org` | facultatif | HTTP access token, lecture projets et dépôts |
| Dépôts locaux | `/srv/git/<sous-dossier>` | — | aucun ; dossier monté en lecture seule |

Les **mots de passe d'application Bitbucket Cloud ne fonctionnent plus depuis le 9 juin 2026** :
utilisez un API token.

Sans token, l'accès est anonyme : seuls les dépôts publics sont visibles, avec les limites de débit
basses des plateformes.

## Résultat d'un test

| Statut | Signification | Action |
|---|---|---|
| Connexion réussie | identité, version du serveur, scopes et expiration affichés | lire les avertissements (droits d'écriture superflus, expiration proche…) |
| Authentification refusée | token absent, invalide, expiré ou révoqué | régénérer le token |
| Permissions insuffisantes | scope ou permission manquant (le message liste les scopes manquants) | recréer le token avec les bons droits |
| Limite de requêtes atteinte | quota de l'API épuisé | réessayer après le délai indiqué |
| Introuvable | mauvaise URL | vérifier l'URL ou l'URL d'API (options avancées) |
| Serveur injoignable | DNS, pare-feu, proxy, délai dépassé | vérifier le réseau ; proxy via `ACS_JAVA_PROXY_OPTS` |
| Certificat TLS non reconnu | autorité interne inconnue | `ACS_GIT_CA_BUNDLE_IN_CONTAINER` |
| Réponse inattendue | redirection, page HTML, mauvais produit | vérifier le type de plateforme et l'URL |
| Destination interdite | politique de sécurité (adresse de métadonnées, HTTP non chiffré, chemin hors `/srv/git`) | voir [security.md](security.md) |

Changer l'adresse d'une connexion vers un autre serveur oblige à ressaisir le token.
