# Connexions Git — guide administrateur

Page **Connexions Git** (rôle ADMIN pour créer, modifier, tester et supprimer ; lecture pour tous).
Utilisez toujours un token **en lecture seule** dédié à SAYTU.

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
utilisez un API token. Un *access token* de workspace, projet ou dépôt n'appartient à aucun
utilisateur : son workspace ne peut pas être découvert automatiquement, ajoutez-le par son nom
(voir ci-dessous).

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
| Serveur injoignable | DNS, pare-feu, proxy, délai dépassé | vérifier le réseau ; proxy via `SAYTU_JAVA_PROXY_OPTS` |
| Certificat TLS non reconnu | autorité interne, ou proxy / antivirus qui inspecte le HTTPS | voir « Proxy d'inspection HTTPS » ci-dessous |
| Réponse inattendue | redirection, page HTML, mauvais produit | vérifier le type de plateforme et l'URL |
| Destination interdite | politique de sécurité (adresse de métadonnées, HTTP non chiffré, chemin hors `/srv/git`) | voir [security.md](security.md) |

Changer l'adresse d'une connexion vers un autre serveur oblige à ressaisir le token.

## Découvrir et sélectionner les dépôts (page « Organisations & dépôts »)

1. Choisir la connexion, puis **Découvrir les organisations** : compte personnel, organisations,
   groupes et sous-groupes, workspaces ou projets visibles avec le token.
2. Pour une organisation publique dont vous n'êtes pas membre (ex. `kubernetes` sur GitHub), un
   groupe GitLab par son chemin (ex. `gitlab-org/security-products`) ou le workspace d'un access token
   Bitbucket : **Ajouter par nom**.
3. Cocher **Auditer cette organisation**, puis :
   * **Tous les dépôts (y compris futurs)** : chaque dépôt présent ou à venir est audité ;
   * sinon **Charger les dépôts** et cocher ceux à auditer (recherche et pagination disponibles).
4. Les dépôts archivés ne sont jamais audités. Un élément qui n'existe plus sur la plateforme est
   signalé, pas supprimé : sa sélection est conservée s'il réapparaît.

Une synchronisation interrompue (limite de requêtes, réseau) conserve ce qui a déjà été lu et
n'efface rien ; relancez-la plus tard. Plafond : 10 000 éléments par synchronisation.

## Branches et scanners (page « Scanners & branches »)

Pour chaque dépôt audité :

| Mode | Branches analysées |
|---|---|
| Branche par défaut | la branche par défaut du dépôt (`main`, `master`…) |
| main, master, develop | celles des trois qui existent au moment du scan |
| Liste personnalisée | les branches choisies dans la liste de la plateforme ou saisies (règles de nommage git) |

La même page active ou désactive chaque scanner et fixe ses limites (durée, temps CPU, mémoire).
Un scanner désactivé réduit la couverture affichée avec les scores : il n'est jamais compté comme
« aucune vulnérabilité ».

## Proxy d'inspection HTTPS ou autorité interne

Sur un réseau d'entreprise, une passerelle (Netskope, Zscaler, Fortinet, Palo Alto…) ou un antivirus
(Kaspersky, ESET, Avast…) peut déchiffrer le HTTPS et le re-signer avec sa propre autorité. Le
navigateur l'accepte (autorité installée dans le système) mais pas Java : le test affiche
« Certificat TLS non reconnu », même pour gitlab.com ou github.com.

**Diagnostic** : ouvrir la forge dans le navigateur, cadenas → certificat → émetteur. Si l'émetteur
est le nom de l'entreprise, d'un proxy ou d'un antivirus, c'est une interception.

**Correction** : exporter ce certificat d'autorité au format Base-64 (PEM, `.cer` ou `.pem`), puis :

* Docker Compose : le déposer dans `./data/ca/` et renseigner
  `SAYTU_GIT_CA_BUNDLE_IN_CONTAINER=/etc/saytu/ca/<fichier>` dans `.env` ;
* exécution directe : `SAYTU_GIT_CA_BUNDLE=<chemin du fichier>` avant `java -jar` ;
* poste Windows sans Docker, alternative rapide : faire utiliser à Java le magasin de Windows :
  `java -Djavax.net.ssl.trustStore=NONE -Djavax.net.ssl.trustStoreType=Windows-ROOT -jar ...`

Le proxy d'inspection voit passer les requêtes, y compris l'en-tête qui porte le token : utilisez un
token en lecture seule, à durée de vie courte.
