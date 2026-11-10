# Notes de sécurité

Document vivant : chaque phase y ajoute ses mesures et ses risques résiduels. Exploitation
(sauvegarde, mise à jour, installation isolée) : [operations.md](operations.md).

## Connexions Git (phase 2)

### Tokens
| Étape | Mesure |
|---|---|
| Saisie | Champ mot de passe, jamais renvoyé par l'API (`hasToken` seulement), masqué dans `toString()` des requêtes. |
| Stockage | AES-256-GCM, IV aléatoire, données associées = `git_connection:<id>` (un chiffré copié sur une autre ligne ne se déchiffre pas), identifiant de clé pour la rotation. |
| Clé maître | `SAYTU_MASTER_KEY` (32 octets base64), hors base. L'application refuse de démarrer sans clé valide. |
| Rotation | Nouvelle clé dans `SAYTU_MASTER_KEY`, ancienne dans `SAYTU_PREVIOUS_MASTER_KEYS` ; chaque token est re-chiffré au premier test réussi. |
| Usage | Déchiffré dans une `SensitiveValue` le temps d'un appel, puis effacé. |
| Changement d'hôte | Modifier l'URL vers un autre hôte (ou port, ou schéma) **exige de ressaisir le token** : un token stocké ne peut pas être détourné vers un autre serveur en éditant l'URL. |
| Journal | Création, modification, suppression, test et changement de token sont tracés dans `audit_event` (table en ajout seul), sans le token. |

### Requêtes sortantes (anti-SSRF)
Avant chaque requête, `EndpointPolicy` résout l'hôte et refuse :

* les schémas autres que `https` (`http` seulement si `SAYTU_GIT_ALLOW_PLAIN_HTTP=true`) ;
* les identifiants dans l'URL ;
* les adresses de métadonnées cloud et link-local (169.254.0.0/16, fe80::/10, `fd00:ec2::254`,
  100.100.100.200), l'adresse non spécifiée, multicast, broadcast, 0.0.0.0/8 ;
* le loopback, sauf `SAYTU_GIT_ALLOW_LOOPBACK=true` (développement).

Les plages privées (10/8, 172.16/12, 192.168/16, fc00::/7) restent autorisées : c'est là que vivent
les GitLab et Bitbucket auto-hébergés. Les redirections ne sont jamais suivies.

**Risque résiduel** : rebinding DNS entre la vérification et la connexion. Atténuation recommandée
en production : résolveur DNS interne de confiance et filtrage de sortie (pare-feu) n'autorisant que
les forges connues.

### Découverte (phase 3)
* Les curseurs de pagination envoyés au navigateur sont de simples numéros (page ou position) : les
  URL de page suivante renvoyées par les plateformes (`Link`, `next`) ne sont jamais suivies telles
  quelles : un curseur forgé ne peut donc pas détourner une requête — et le token — vers un autre hôte.
* Les URL de clone annoncées par les plateformes sont nettoyées de tout identifiant
  (`https://user@bitbucket.org/...`) ; la base refuse toute URL de clone contenant des identifiants.
* Les noms de branches saisis respectent les règles de `git check-ref-format` (contrôle applicatif
  et contrainte SQL) : impossible d'injecter une option (`--upload-pack=...`) ou un chemin (`..`).
* Les dépôts locaux sont lus sans lancer git (fichiers `HEAD`, `refs/heads`, `packed-refs`) ; un
  fichier `.git` pointant hors de la racine autorisée est ignoré.
* Appels réseau hors transaction, une seule synchronisation à la fois par connexion.

### Dépôts locaux
Seuls les répertoires situés sous `SAYTU_LOCAL_REPOS_ROOT` (monté en lecture seule sur `/srv/git`)
sont acceptés, après résolution des liens symboliques.

### TLS
La vérification des certificats ne peut pas être désactivée. Pour une autorité interne : déposer le
certificat PEM dans `./data/ca/` et renseigner `SAYTU_GIT_CA_BUNDLE_IN_CONTAINER`.

## Authentification de l'interface (phase 2)
Voir [ADR-0006](adr/0006-oidc-spa.md) : code + PKCE, jetons en mémoire, validation de l'ID token,
jeton envoyé uniquement à `/api/v1`, pas de redirection ouverte. L'API reste la seule autorité :
rôles vérifiés côté serveur (`@PreAuthorize`), l'interface masque seulement les actions interdites.

## Isolation des scanners (phase 8)

Le code analysé n'est **jamais exécuté** (aucun script de build, clone sans hooks ni sous-modules). Le risque
restant est une faille dans un outil d'analyse déclenchée par un fichier piégé du dépôt. Pour en limiter les
conséquences, le worker démarre en `root` **avec un jeu réduit de capacités** (`SETUID`, `SETGID`, `CHOWN`,
`DAC_OVERRIDE`, `FOWNER`, `KILL`, sous-ensemble des capacités Docker par défaut ; `no-new-privileges`, système de
fichiers en lecture seule) et lance les outils de chaque audit sous un **compte dédié** :

| Mesure | Effet |
|---|---|
| un uid/gid par audit en cours (20000, 20001…), via `setpriv` : aucun groupe supplémentaire, aucune capacité, `no_new_privs` | un scanner ne peut lire ni la mémoire ni l'environnement du worker (`/proc/<worker>/environ` contient le mot de passe de la base et `SAYTU_MASTER_KEY`), ni le jeton Git, ni les fichiers d'un autre audit |
| répertoire du job `0750 root:<gid du job>`, sources appartenant à `root`, répertoire de travail de chaque outil `0700` à l'uid du job, racine des jobs `0711` | les sources ne peuvent pas être modifiées pour tromper l'outil suivant ; les autres jobs ne sont pas listables |
| après chaque outil, tous les processus de l'uid du job sont tués | aucun processus détaché (double fork, `setsid`) ne survit à l'analyse |
| règle `iptables -m owner` posée par `worker-entrypoint.sh`, qui démarre ensuite le worker **sans** `NET_ADMIN` | les scanners n'ont aucun accès réseau (ni Internet, ni la base, ni Keycloak, ni l'actuator local) ; la règle ne peut plus être retirée |
| limites `prlimit` (CPU, taille de fichiers, descripteurs, pas de core dump), mémoire et délai surveillés (phase 4) | inchangé |

Restent exécutés par le worker lui-même, car ils ont besoin du réseau ou du jeton : `git clone`, `git ls-remote`
et le téléchargement de la base Trivy (données publiques). La base Trivy est rendue lisible (`a+rX`) par les
comptes de scanners, modifiable par le worker seul.

L'état réel est affiché dans **Scanners & branches** (« Isolation des scanners ») et dans le journal du
worker (`scanner isolation: dedicated account yes, network blocked`) :

* **compte dédié « non »** : le worker ne tourne pas en root (image lancée sans le `docker-compose.yml`
  fourni) ; `SAYTU_SCAN_ISOLATION_MODE=REQUIRED` empêche alors le worker de démarrer ;
* **réseau « ouvert »** : le noyau a refusé la règle de pare-feu (module `owner` / `nf_tables` absent, ou
  hôte qui interdit `NET_ADMIN`) ; la raison est affichée. Les scanners restent sous compte dédié.

Risques résiduels : les scanners voient le système de fichiers de l'image en lecture (binaires, règles —
aucun secret) ; pas d'espace de noms séparé (le profil seccomp par défaut de Docker interdit `unshare` sans
`CAP_SYS_ADMIN`, que SAYTU ne demande pas) ; une faille du noyau reste hors de portée de ces mesures.
