# Notes de sécurité

Document vivant : chaque phase y ajoute ses mesures et ses risques résiduels. Le guide
d'exploitation complet est prévu en phase 8.

## Connexions Git (phase 2)

### Tokens
| Étape | Mesure |
|---|---|
| Saisie | Champ mot de passe, jamais renvoyé par l'API (`hasToken` seulement), masqué dans `toString()` des requêtes. |
| Stockage | AES-256-GCM, IV aléatoire, données associées = `git_connection:<id>` (un chiffré copié sur une autre ligne ne se déchiffre pas), identifiant de clé pour la rotation. |
| Clé maître | `ACS_MASTER_KEY` (32 octets base64), hors base. L'application refuse de démarrer sans clé valide. |
| Rotation | Nouvelle clé dans `ACS_MASTER_KEY`, ancienne dans `ACS_PREVIOUS_MASTER_KEYS` ; chaque token est re-chiffré au premier test réussi. |
| Usage | Déchiffré dans une `SensitiveValue` le temps d'un appel, puis effacé. |
| Changement d'hôte | Modifier l'URL vers un autre hôte (ou port, ou schéma) **exige de ressaisir le token** : un token stocké ne peut pas être détourné vers un autre serveur en éditant l'URL. |
| Journal | Création, modification, suppression, test et changement de token sont tracés dans `audit_event` (table en ajout seul), sans le token. |

### Requêtes sortantes (anti-SSRF)
Avant chaque requête, `EndpointPolicy` résout l'hôte et refuse :

* les schémas autres que `https` (`http` seulement si `ACS_GIT_ALLOW_PLAIN_HTTP=true`) ;
* les identifiants dans l'URL ;
* les adresses de métadonnées cloud et link-local (169.254.0.0/16, fe80::/10, `fd00:ec2::254`,
  100.100.100.200), l'adresse non spécifiée, multicast, broadcast, 0.0.0.0/8 ;
* le loopback, sauf `ACS_GIT_ALLOW_LOOPBACK=true` (développement).

Les plages privées (10/8, 172.16/12, 192.168/16, fc00::/7) restent autorisées : c'est là que vivent
les GitLab et Bitbucket auto-hébergés. Les redirections ne sont jamais suivies.

**Risque résiduel** : rebinding DNS entre la vérification et la connexion. Atténuation recommandée
en production : résolveur DNS interne de confiance et filtrage de sortie (pare-feu) n'autorisant que
les forges connues.

### Dépôts locaux
Seuls les répertoires situés sous `ACS_LOCAL_REPOS_ROOT` (monté en lecture seule sur `/srv/git`)
sont acceptés, après résolution des liens symboliques.

### TLS
La vérification des certificats ne peut pas être désactivée. Pour une autorité interne : déposer le
certificat PEM dans `./data/ca/` et renseigner `ACS_GIT_CA_BUNDLE_IN_CONTAINER`.

## Authentification de l'interface (phase 2)
Voir [ADR-0006](adr/0006-oidc-spa.md) : code + PKCE, jetons en mémoire, validation de l'ID token,
jeton envoyé uniquement à `/api/v1`, pas de redirection ouverte. L'API reste la seule autorité :
rôles vérifiés côté serveur (`@PreAuthorize`), l'interface masque seulement les actions interdites.
