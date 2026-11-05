# Installer SAYTU sur un poste Windows (WSL 2 + Docker Engine)

Docker Engine est installé **dans une distribution Linux sous WSL 2** : gratuit et open source
(Apache-2.0), sans Docker Desktop (dont la licence est payante pour les organisations de plus de
250 salariés ou 10 M$ de chiffre d'affaires). Les scripts du projet s'exécutent tels quels.

Prévoir 8 Go de RAM pour WSL et 15 à 20 minutes pour la première construction.

## 1. Distribution Linux

Dans PowerShell ou Cmder :
```
wsl --list --verbose          # une distribution existe déjà ?
wsl --install -d Ubuntu-24.04 # sinon, l'installer (droits administrateur parfois nécessaires)
```
Créer l'utilisateur Linux demandé au premier lancement.

Mémoire allouée à WSL : fichier `%UserProfile%\.wslconfig`
```
[wsl2]
memory=8GB
```
puis `wsl --shutdown`.

Les commandes suivantes se tapent **dans Ubuntu** (`wsl -d Ubuntu-24.04`).

## 2. Proxy d'inspection HTTPS (Netskope, Zscaler…) — seulement si votre réseau en a un

Symptôme : `curl https://github.com` échoue dans Ubuntu avec une erreur de certificat.

1. Exporter le certificat racine du proxy depuis le navigateur Windows (cadenas → certificat →
   chemin d'accès → certificat du haut → « Base-64 encodé X.509 »), par exemple dans
   `C:\Users\<vous>\certs\proxy-ca.cer`.
2. L'ajouter aux autorités de confiance d'Ubuntu :
   ```bash
   sudo cp /mnt/c/Users/<vous>/certs/proxy-ca.cer /usr/local/share/ca-certificates/proxy-ca.crt
   sudo update-ca-certificates
   ```

## 3. Docker Engine

Dépôt officiel Docker pour Ubuntu :
```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl git
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"
```
Fermer Ubuntu, `wsl --shutdown` depuis Windows, rouvrir Ubuntu, puis vérifier :
```bash
docker run --rm hello-world
docker compose version
```
Si Docker ne démarre pas seul : `sudo service docker start` (ou activer systemd : `[boot]
systemd=true` dans `/etc/wsl.conf`, puis `wsl --shutdown`).

Avec un proxy d'inspection, Docker utilise les autorités d'Ubuntu ajoutées à l'étape 2 pour
télécharger les images ; s'il a démarré avant, `sudo service docker restart`.

## 4. SAYTU

Cloner **dans le système de fichiers Linux** (`~`), pas sous `/mnt/c` : beaucoup plus rapide, et
pas de problème de fins de ligne.
```bash
cd ~
git clone https://github.com/momos95/saytu.git
cd saytu
# proxy d'inspection uniquement : le certificat sert aussi pendant la construction des images
cp /mnt/c/Users/<vous>/certs/proxy-ca.cer data/ca/
scripts/generate-secrets.sh
grep SAYTU_INITIAL_ADMIN_PASSWORD .env
docker compose up -d --build
docker compose ps        # postgres, keycloak, api, web : "healthy"
```

Construction plus rapide (sans les tests unitaires) : `SAYTU_SKIP_TESTS=true` dans `.env`.

## 5. Utiliser

Depuis le navigateur Windows :
* interface : <http://localhost:8080> — utilisateur `admin`, mot de passe lu dans `.env` (à
  changer à la première connexion, avec configuration d'une application TOTP) ;
* console Keycloak : <http://localhost:8180>.

Dépôts locaux : les placer dans `~/saytu/data/local-repos/`, ils apparaissent sous `/srv/git`.

## Dépannage

| Problème | Commande / solution |
|---|---|
| Un service n'est pas « healthy » | `docker compose logs <service> \| tail -100` |
| Erreur de certificat pendant `mvn` ou `npm` | certificat du proxy absent de `data/ca/` (format Base-64), puis `docker compose build --no-cache` |
| « Certificat TLS non reconnu » en testant une connexion Git | même cause : certificat dans `data/ca/`, puis `docker compose up -d --build api` |
| Repartir de zéro | `docker compose down -v`, supprimer `.env`, reprendre à `scripts/generate-secrets.sh` |

## Sans WSL

`scripts\generate-secrets.ps1` génère `.env` sous PowerShell :
`powershell -ExecutionPolicy Bypass -File scripts\generate-secrets.ps1`.
Il faut alors un moteur Docker sous Windows (Docker Desktop, sous réserve de sa licence, ou
Rancher Desktop / Podman Desktop, gratuits).
