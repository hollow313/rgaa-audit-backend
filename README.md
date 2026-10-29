# RGAA Audit - Backend & Serveur de Licences

Serveur autonome de gestion de licences, révocation (CRL) et distribution des mises à jour pour le plugin WordPress **RGAA Audit**.

Le serveur s'exécute dans un conteneur léger **Linux Alpine**, avec un utilisateur non-privilégié (UID 568), écoute sur le port **30019**, et conserve les paires de clés cryptographiques ainsi que la base de données dans un volume monté (**bind mount**).

---

## Fonctionnalités

1. **Interface Web d'administration (Port 30019)** : tableau de bord interactif accessible via navigateur pour émettre, consulter, copier et révoquer les clés de licence en direct.
2. **Génération de licences signées (RSA-SHA256)** : compatible avec le contrat de vérification hors ligne du plugin WordPress (`openssl_verify()`).
3. **Liste de révocation signée (CRL)** : distribution de la liste des licences annulées ou remboursées avec horodatage anti-rejeu (`next_update`).
4. **Distribution des mises à jour** : manifeste signé (`/v1/updates/:slug`) et téléchargement sécurisé des archives ZIP avec vérification SHA-256.
5. **Enregistrement des activations (opt-in)** : suivi des domaines actifs sans collecte d'IP ni de données personnelles pour détecter le partage abusif.
6. **Webhooks e-commerce (Polar / Paddle)** : émission et révocation automatisées après paiement, avec idempotence stricte.
7. **CLI intégrée** : génération, révocation, vérification et publication directement en ligne de commande.

---

## Interface Web Dashboard & Sécurité

L'accès au tableau de bord s'effectue via votre navigateur :

```
http://<IP-du-serveur>:30019/?token=<ADMIN_TOKEN>
```
ou directement `http://<IP-du-serveur>:30019/` (une boîte de dialogue modale s'affiche pour renseigner votre `ADMIN_TOKEN`). Aucun identifiant ni mot de passe n'est demandé : seul le jeton secret est requis.

Le jeton est ensuite mémorisé localement dans votre navigateur (`localStorage`), et vous pouvez à tout moment le modifier ou vous déconnecter via le bouton **`🔒 Token Admin`** situé dans l'en-tête.

Fonctionnalités disponibles sur l'interface :
- **Émission de clés** : formulaire guidé (email, plan solo/agence, nombre de sites, domaine ou `*`, expiration).
- **Gestion des licences** : tableau complet avec recherche instantanée, suivi des activations par rapport au quota (`✓ 1 / 1 site(s)`), copie de la clé signée en 1 clic et révocation immédiate.
- **Détection du partage** : onglet dédié listant les clés actives constatées sur plus d'un domaine distinct.
- **Clé publique PEM** : visualisation et copie en un clic de la clé publique à intégrer dans le plugin WordPress.

---

## Spécifications du Conteneur

| Paramètre | Valeur |
|---|---|
| Image de base | Linux Alpine (`node:22-alpine`) |
| Utilisateur conteneur | `568:568` (`appuser`) |
| Port interne exposé | `30019` |
| Volume persistant (clés & données) | `/keys` |
| Emplacement clé privée | `/keys/private.pem` (permissions `0600`) |
| Emplacement clé publique | `/keys/public.pem` (permissions `0644`) |
| Base de données SQLite | `/keys/licenses.sqlite` |

---

## Démarrage Rapide

### 1. Avec Docker Compose (Recommandé)

Créez le répertoire local pour stocker les clés et attribuez les permissions à l'utilisateur `568` :

```bash
mkdir -p keys
# Sur Linux / serveur :
chown -R 568:568 keys
chmod 700 keys
```

Lancez le service :

```bash
docker compose up -d
```

Au premier démarrage, le serveur génère automatiquement la paire de clés RSA 2048 bits dans le dossier `keys/` si elle n'existe pas encore.

### 2. Avec Docker CLI

```bash
docker run -d \
  --name rgaa-license-server \
  --user 568:568 \
  -p 30019:30019 \
  -e ADMIN_TOKEN="monSecretAdmin123!" \
  -e PAYMENT_PROVIDERS="none" \
  -v $(pwd)/keys:/keys \
  --restart unless-stopped \
  holloow313/rgaa-audit-backend:latest
```

---

## Variables d'Environnement

| Variable | Défaut | Description |
|---|---|---|
| `PORT` | `30019` | Port d'écoute HTTP du serveur |
| `HOST` | `0.0.0.0` | Adresse d'écoute (toutes interfaces) |
| `ADMIN_TOKEN` | *(vide)* | Jeton secret obligatoire pour protéger toutes les routes `/api/*` et le dashboard Web `GET /` |
| `PAYMENT_PROVIDERS` | `polar` | Fournisseurs de paiement actifs : `polar`, `paddle`, ou `none` (si émission manuelle / hors ligne) |
| `POLAR_WEBHOOK_SECRET` | *(vide)* | Clé secrète Standard Webhooks Polar (commençant par `whsec_...`) |
| `PADDLE_WEBHOOK_SECRET` | *(vide)* | Clé secrète de signature des webhooks Paddle |
| `KEYS_DIR` | `/keys` | Répertoire de stockage des clés et données SQLite |
| `KEY_PATH` | `/keys/private.pem` | Chemin vers la clé privée RSA |
| `PUBLIC_KEY_PATH` | `/keys/public.pem` | Chemin vers la clé publique RSA |
| `DB_PATH` | `/keys/licenses.sqlite` | Chemin vers le fichier SQLite |
| `AUTO_GENERATE_KEYS` | `true` | Génère automatiquement le trousseau RSA au premier lancement s'il est absent |
| `EVENTS_RETENTION_DAYS` | `90` | Rétention RGPD des événements de paiement pour l'idempotence (en jours, min. 7) |
| `SMTP_URL` | *(vide)* | URL SMTP pour l'envoi des clés par email (`smtp://user:pass@host:587`) |
| `SMTP_FROM` | `licenses@exemple.fr` | Adresse d'expéditeur des emails transactionnels |
| `PUBLIC_BASE_URL` | `https://updates.rgaa-audit.eu` | URL publique de base utilisée dans les emails de livraison de clé |
| `CRL_VALIDITY_HOURS` | `24` | Durée de validité de la CRL avant régénération du cache |

---

## Déploiement sur Serveur & Résolution du statut « Déploiement » (TrueNAS SCALE / Docker)

Les orchestrateurs de conteneurs sur serveur (TrueNAS SCALE, Docker Compose, Kubernetes, Portainer, etc.) surveillent la disponibilité applicative via la sonde `HEALTHCHECK` qui interroge périodiquement `http://127.0.0.1:30019/healthz`.

### Pourquoi le conteneur reste-t-il en statut jaune « Déploiement » ?

TrueNAS SCALE affiche le badge jaune **« Déploiement »** avec des métriques à `N/A` tant que le conteneur n'a pas été déclaré **sain (Healthy)** ou que la sonde de disponibilité échoue. Voici les 3 causes fréquentes :

#### 1. Le Healthcheck renvoie `503` (Cause la plus fréquente : Webhook Polar non configuré)
Par défaut, `PAYMENT_PROVIDERS` est configuré sur `polar`. Si la variable `POLAR_WEBHOOK_SECRET` n'a pas encore été renseignée dans la configuration de votre conteneur, l'endpoint `/healthz` renvoie volontairement un code **`503`** (`{"ok":false,"error":"webhook_secret_missing"}`). Cela évite qu'un serveur de production encaisse des paiements sans pouvoir traiter les webhooks.
Tant que `/healthz` renvoie 503, Docker considère le conteneur comme `unhealthy`, et TrueNAS l'affiche indéfiniment en statut **« Déploiement »**.

**Comment passer immédiatement au statut « En cours d'exécution » (Actif / Vert) :**
* **Cas 1 : Vous n'avez pas encore configuré Polar (mode test ou émission manuelle)** :
  Ajoutez simplement la variable d'environnement suivante dans les paramètres de l'application sur TrueNAS :
  ```env
  PAYMENT_PROVIDERS=none
  ```
  Le healthcheck renverra immédiatement `200 {"ok":true,"db":true}` et le conteneur passera instantanément en vert !
* **Cas 2 : Vous utilisez Polar pour les paiements en ligne** :
  Renseignez simplement votre secret de webhook Polar dans les variables d'environnement de l'application :
  ```env
  POLAR_WEBHOOK_SECRET=whsec_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
  ```
  Dès que le secret est détecté, `/healthz` répond `200` et TrueNAS bascule sur « En cours d'exécution ».

#### 2. Sonde de santé TrueNAS (Readiness Probe) configurée sur `/` au lieu de `/healthz`
Si vous avez activé une sonde de santé (Readiness Probe / Liveness Probe) dans l'interface TrueNAS :
* Ne configurez **jamais** le chemin de sonde sur `/` (la racine), car `GET /` renvoie désormais un code **`401 Unauthorized`** pour protéger le tableau de bord d'administration. TrueNAS attend un code `200` et considérera le conteneur comme en échec.
* Configurez le chemin de sonde sur : **`/healthz`** (Port : **`30019`**), ou désactivez simplement les sondes personnalisées de TrueNAS (le conteneur dispose déjà de son propre `HEALTHCHECK` Docker intégré).

#### 3. Permissions du Dataset de stockage `/keys` (UID 568)
Le conteneur tourne sous l'utilisateur de sécurité non-root `appuser` avec le **UID/GID `568:568`** (qui correspond d'ailleurs à l'utilisateur système `apps` sur TrueNAS SCALE).
* Assurez-vous que le Dataset monté dans `/keys` autorise la lecture/écriture pour l'utilisateur `568` (`apps`), ou appliquez les permissions :
  ```bash
  chown -R 568:568 /mnt/<pool>/<dataset-keys>
  chmod -R 770 /mnt/<pool>/<dataset-keys>
  ```

---

## Utilisation de la CLI

Vous pouvez exécuter les commandes d'administration directement dans le conteneur en cours d'exécution :

### Émettre une clé de licence

```bash
docker exec -it rgaa-license-server node src/cli.js issue \
  --email client@domaine.fr \
  --plan solo \
  --sites 1 \
  --domain https://domaine.fr \
  --expires 2028-12-31
```

Sortie :
```text
--- Licence générée avec succès ---
ID:      8f14e45f-7f32-4d56-b08e-173614271920
Email:   client@domaine.fr
Plan:    solo
Sites:   1
Domaine: domaine.fr
Expire:  2028-12-31

Clé de licence :
<payload_base64url>.<signature_base64url>
-----------------------------------
```

### Vérifier une clé de licence

```bash
docker exec -it rgaa-license-server node src/cli.js verify --key "<clé>"
```

### Révoquer une licence

```bash
docker exec -it rgaa-license-server node src/cli.js revoke --id <uuid> --reason refund
```

### Lister les licences et identifier le partage abusif

```bash
# Toutes les licences
docker exec -it rgaa-license-server node src/cli.js list

# Uniquement les licences actives détectées sur plus d'un domaine
docker exec -it rgaa-license-server node src/cli.js list --shared
```

### Publier une nouvelle version du plugin

```bash
docker exec -it rgaa-license-server node src/cli.js publish \
  --zip /keys/releases/rgaa-audit-0.2.0.zip \
  --version 0.2.0 \
  --requires 6.5 \
  --tested 6.8 \
  --requires-php 8.1
```

---

## Endpoints HTTP

| Méthode | Route | Description |
|---|---|---|
| `GET` | `/healthz` | Vérification de santé (`{ "ok": true, "db": true }`) |
| `GET` | `/v1/public-key` | Récupération de la clé publique RSA en format PEM |
| `POST` | `/v1/activate` | Activation d'un domaine client et respect du quota de sites |
| `POST` | `/v1/deactivate` | Désactivation d'un domaine pour libérer un slot de licence |
| `GET` | `/v1/crl` | Liste de révocation signée (`Cache-Control: 3600`) |
| `GET` | `/v1/updates` / `/:slug` | Manifeste de mise à jour signé (exige `?key=...`) |
| `GET` | `/v1/download/:version.zip?key=…` | Téléchargement du ZIP après validation de la clé |
| `POST` | `/v1/resend-key` | Renvoi de l'email avec la clé de licence (exige `ADMIN_TOKEN`) |
| `POST` | `/v1/webhook/polar` | Webhook Standard Webhooks Polar pour émission automatique |
| `POST` | `/v1/webhook/paddle` | Webhook des commandes Paddle |
| `GET` | `/api/licenses` | Liste des licences avec activations et clés (exige `ADMIN_TOKEN`) |
| `POST` | `/api/licenses` | Création transactionnelle de licence (exige `ADMIN_TOKEN`) |
| `POST` | `/api/licenses/:id/revoke` | Révocation immédiate d'une licence (exige `ADMIN_TOKEN`) |
| `DELETE` | `/api/licenses/:id` | Suppression définitive d'une licence et de ses activations (exige `ADMIN_TOKEN`) |
| `POST` | `/api/licenses/purge` | Purge ciblée des licences de test ou révoquées (exige `ADMIN_TOKEN`) |
| `GET` | `/api/releases` | Liste des versions publiées du plugin avec SHA-256 et métriques (exige `ADMIN_TOKEN`) |
| `POST` | `/api/releases` | Publication directe d'une archive ZIP du plugin avec contrôle d'intégrité (exige `ADMIN_TOKEN`) |
| `DELETE` | `/api/releases/:version` | Suppression d'une version publiée (refuse la dernière version active, exige `ADMIN_TOKEN`) |
| `GET` | `/api/stats` | Métriques et statistiques du parc de licences |

---

## Format Cryptographique des Clés

La clé de licence se compose de deux parties séparées par un point :

```
<payload_base64url>.<signature_base64url>
```

1. **Payload** : Représentation JSON des données encodée en `base64url` sans padding :
   ```json
   {
     "id": "8f14e45f-...",
     "license_id": "8f14e45f-...",
     "plan": "solo",
     "sites": 1,
     "expires": "2028-12-31",
     "domain": "domaine.fr",
     "issued_at": "2026-10-29T12:00:00.000Z"
   }
   ```
2. **Signature** : Signature RSA-SHA256 portant sur les octets bruts du JSON du payload, encodée en `base64url` sans padding.

La vérification côté client WordPress est effectuée hors ligne à l'aide de `openssl_verify()` et de la clé publique embarquée.

---

## Intégration CI/CD (GitHub Actions)

Le workflow `.github/workflows/docker-publish.yml` déclenche automatiquement :
1. L'exécution de la suite de tests unitaires et d'intégration (`npm test`).
2. La construction de l'image Docker Alpine multi-plateforme via Docker Buildx.
3. La publication sur Docker Hub avec les tags `latest`, le tag de version sémantique (`v*.*.*`), et le hash de commit court.

Les secrets requis sur le dépôt GitHub sont :
- `DOCKERHUB_USERNAME` (ou `DOCKER_USERNAME`)
- `DOCKERHUB_TOKEN` (ou `DOCKER_PASSWORD`)

---

## Tests

Pour exécuter la suite de tests en local :

```bash
npm test
```
