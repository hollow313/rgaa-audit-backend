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

## Interface Web Dashboard

Ouvrez simplement l'adresse suivante dans votre navigateur :

```
http://<IP-du-serveur>:30019/
```

Fonctionnalités disponibles sur l'interface :
- **Émission de clés** : formulaire guidé (email, plan solo/agence, nombre de sites, domaine ou `*`, expiration).
- **Gestion des licences** : tableau complet avec recherche instantanée, copie de la clé signée en 1 clic et révocation.
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
  -v $(pwd)/keys:/keys \
  --restart unless-stopped \
  holloow313/rgaa-audit-backend:latest
```

---

## Variables d'Environnement

| Variable | Défaut | Description |
|---|---|---|
| `PORT` | `30019` | Port d'écoute HTTP du serveur |
| `HOST` | `0.0.0.0` | Adresse d'écoute |
| `KEYS_DIR` | `/keys` | Répertoire de stockage des clés et données |
| `KEY_PATH` | `/keys/private.pem` | Chemin vers la clé privée RSA |
| `PUBLIC_KEY_PATH` | `/keys/public.pem` | Chemin vers la clé publique RSA |
| `DB_PATH` | `/keys/licenses.sqlite` | Chemin vers la base SQLite |
| `AUTO_GENERATE_KEYS` | `true` | Génère automatiquement le trousseau RSA s'il est manquant |
| `ADMIN_API_KEY` | *(vide)* | Clé secrète requise pour les routes `/v1/admin/*` |
| `POLAR_WEBHOOK_SECRET` | *(vide)* | Clé secrète de signature des webhooks Polar |
| `PADDLE_WEBHOOK_SECRET` | *(vide)* | Clé secrète de signature des webhooks Paddle |
| `SMTP_URL` | *(vide)* | URL SMTP pour l'envoi des clés par email (`smtp://...`) |
| `SMTP_FROM` | `licenses@exemple.fr` | Expéditeur des emails transactionnels |
| `CRL_VALIDITY_HOURS` | `24` | Durée de validité de la CRL avant expiration du cache |

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
| `POST` | `/v1/activate` | Vérification de licence et enregistrement du domaine |
| `GET` | `/v1/crl` | Liste de révocation signée (`Cache-Control: 3600`) |
| `GET` | `/v1/updates/:slug` | Manifeste de mise à jour signé |
| `GET` | `/v1/download/:version.zip?key=…` | Téléchargement du ZIP après validation de la clé |
| `POST` | `/v1/webhook/polar` | Webhook de traitement des commandes Polar |
| `POST` | `/v1/webhook/paddle` | Webhook de traitement des commandes Paddle |
| `POST` | `/v1/admin/issue` | Émission d'une licence via API (avec `X-Admin-Key`) |
| `POST` | `/v1/admin/revoke` | Révocation d'une licence via API |
| `GET` | `/v1/admin/licenses` | Liste des licences (`?shared=true` disponible) |

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
