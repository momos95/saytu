# ADR-0004 — Chiffrement applicatif des tokens Git

**Statut** : accepté (phase 1), implémentation en phase 2

## Décision
* AES-256-GCM (JCA standard, aucune dépendance), IV aléatoire de 96 bits par chiffrement,
  tag 128 bits ; format stocké : `version(1) || iv(12) || ciphertext || tag(16)`.
* Données associées (AAD) = identifiant de la connexion : un chiffré copié vers une autre ligne
  ne se déchiffre pas.
* Clé maître `ACS_MASTER_KEY` (32 octets base64) fournie par l'environnement, jamais en base ;
  colonne `token_key_id` pour la rotation (ré-chiffrement progressif).
* Le token déchiffré vit dans une `SensitiveValue` le temps d'un appel API ou d'un clone, puis est
  effacé ; il n'apparaît dans aucun DTO, log ou message d'erreur. L'API ne renvoie jamais le token,
  seulement `hasToken`.

## Alternatives écartées
* `pgcrypto` : la clé transiterait dans les requêtes SQL et les journaux PostgreSQL.
* HashiCorp Vault : licence BUSL depuis 2023 ; OpenBao (MPL-2.0) pourra être ajouté plus tard
  comme fournisseur de clé optionnel.
