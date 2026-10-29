# Serveur de licences et de mises à jour — spécification

Document autonome : tout ce qu'il faut pour développer le service à côté du plugin,
sur le NAS. Le plugin, lui, ne change pas de contrat : il continue de vérifier les
signatures **hors ligne**.

---

## 0. Rôle et principes

Le serveur fait trois choses, et rien de plus :

1. **Émettre** une clé signée après un paiement.
2. **Publier** une liste de révocation (CRL) signée.
3. **Livrer** les mises à jour du plugin (manifeste + ZIP).

Principes non négociables :

- **Le site du client ne dépend jamais du serveur.** Si le NAS est éteint, les licences
  en cours restent valides et le plugin fonctionne. Seules les *mises à jour* et la
  *révocation* sont différées.
- **Aucune requête par page vue.** Un appel au maximum toutes les 24 h, en tâche de fond.
- **Aucune télémétrie cachée.** L'appel d'activation est annoncé dans le plugin (opt-in).
- **Opt-in avant tout appel réseau**, pour rester compatible avec les règles de
  wordpress.org sur la version gratuite.

---

## 1. Contrat cryptographique avec le plugin

C'est la partie à respecter à la lettre. Le plugin vérifie avec `openssl_verify()`.

### 1.1 Clé de licence

```
raw       = {"plan":"solo","sites":1,"expires":"2027-10-29","domain":"https://exemple.fr"}
payload   = base64url(raw)                                   # sans padding
signature = base64url(openssl_sign(raw, clé_privée, SHA256))
clé       = payload + "." + signature
```

- `base64url` = base64 standard, `+` → `-`, `/` → `_`, padding `=` supprimé.
- La signature porte sur les **octets bruts du JSON**, pas sur le base64.
- Champs : `plan` (`solo` | `agence`), `sites` (entier, informatif hors multisite),
  `expires` (`YYYY-MM-DD`, comparé par `strtotime()`), `domain`.
- `domain` est **obligatoire**. `"*"` = volontairement illimité.
- Le plugin compare le **host normalisé** : minuscules, `www.` retiré, schéma et port ignorés.

> Le même code de signature est dans `tools/keygen.sh`. Le serveur doit produire
> exactement le même format — c'est le seul moyen que la clé soit acceptée.

### 1.2 CRL (liste de révocation)

```json
{
  "version": 1,
  "issued_at": "2026-10-29T12:00:00Z",
  "next_update": "2026-10-30T12:00:00Z",
  "revoked": [
    { "license_id": "8f14e45f-...", "revoked_at": "2026-10-20T09:00:00Z", "reason": "refund" }
  ]
}
```

Servi sous la même enveloppe signée :

```json
{ "payload": "<base64url(raw)>", "signature": "<base64url(sig)>" }
```

- Même clé privée, même schéma : le plugin vérifie avec la clé publique embarquée.
- `next_update` sert d'anti-replay : le plugin refuse une CRL plus ancienne que la
  dernière qu'il a vue.
- Toute la liste est renvoyée (elle reste petite : quelques dizaines d'entrées).

### 1.3 Manifeste de mise à jour

```json
{
  "slug": "rgaa-audit",
  "version": "0.2.0",
  "requires": "6.5",
  "tested": "6.8",
  "requires_php": "8.1",
  "download_url": "https://updates.exemple.fr/v1/download/0.2.0.zip",
  "sha256": "…",
  "published_at": "2026-11-01T10:00:00Z",
  "changelog": "https://updates.exemple.fr/v1/changelog/0.2.0"
}
```

Même enveloppe signée que la CRL. Le plugin vérifie la signature **avant** de proposer
la mise à jour, puis vérifie le `sha256` du ZIP après téléchargement.

---

## 2. Architecture cible sur le NAS

```
Internet
   │  443 (seul port exposé)
   ▼
Caddy  ──── TLS Let's Encrypt, HSTS, reverse proxy
   │
   ├── api.exemple.fr      → service licences   (Node, port interne 8787)
   └── updates.exemple.fr  → même service       (routes /v1/updates, /v1/download)
```

- **Un seul conteneur applicatif** suffit au début (Node + Fastify ou Express).
- **SQLite** en base : quelques milliers de licences, aucun besoin de Postgres.
- **Clé privée** : fichier monté en lecture seule, permissions `0600`, propriétaire du
  service, hors du webroot. Chargée une fois au démarrage, jamais loggée.
- **Signature** : uniquement dans le handler du webhook et dans le CLI d'émission.
  Pas d'endpoint HTTP public qui signe à la demande.

### 2.1 Pourquoi pas un « worker isolé »

À 500 licences/an, un conteneur unique avec la clé en fichier `0600` est un risque
acceptable : le NAS n'expose que 443, et le service n'a qu'un seul utilisateur système.
Si le volume décolle (> 5 000 licences/an), on sort la clé vers un KMS ou un petit
service de signature séparé — mais pas avant.

### 2.2 Docker compose (squelette)

```yaml
services:
  caddy:
    image: caddy:2
    ports: ["443:443", "80:80"]
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
    depends_on: [api]

  api:
    build: .
    restart: unless-stopped
    environment:
      - DB_PATH=/data/licenses.sqlite
      - KEY_PATH=/secrets/private.pem
      - PUBLIC_KEY_PATH=/secrets/public.pem
      - POLAR_WEBHOOK_SECRET=…
      - SMTP_URL=…
    volumes:
      - db:/data
      - ./secrets:/secrets:ro      # 0600, jamais dans git
    expose: ["8787"]

volumes:
  caddy_data:
  db:
```

```
# Caddyfile
api.exemple.fr {
    reverse_proxy api:8787
}
updates.exemple.fr {
    reverse_proxy api:8787
}
```

---

## 3. Base de données

```sql
CREATE TABLE licenses (
  id            TEXT PRIMARY KEY,              -- uuid v4, DANS le payload signé
  email         TEXT NOT NULL,
  plan          TEXT NOT NULL,                 -- solo | agence
  sites         INTEGER NOT NULL DEFAULT 1,
  domain        TEXT NOT NULL,                 -- host normalisé, ou '*'
  expires_at    TEXT NOT NULL,                 -- YYYY-MM-DD
  status        TEXT NOT NULL DEFAULT 'active',-- active | revoked | refunded
  provider      TEXT NOT NULL,                 -- polar | paddle
  provider_ref  TEXT,                          -- id d'abonnement / de commande
  created_at    TEXT NOT NULL,
  revoked_at    TEXT,
  revoke_reason TEXT
);
CREATE UNIQUE INDEX idx_licenses_provider_ref ON licenses(provider, provider_ref);

CREATE TABLE activations (
  license_id     TEXT NOT NULL,
  domain         TEXT NOT NULL,                -- host normalisé
  plugin_version TEXT,
  first_seen     TEXT NOT NULL,
  last_seen      TEXT NOT NULL,
  PRIMARY KEY (license_id, domain)
);

CREATE TABLE events (                          -- idempotence des webhooks
  id          TEXT PRIMARY KEY,                -- id d'événement du MoR
  type        TEXT NOT NULL,
  received_at TEXT NOT NULL
);

CREATE TABLE releases (
  version      TEXT PRIMARY KEY,
  zip_path     TEXT NOT NULL,
  sha256       TEXT NOT NULL,
  requires     TEXT,
  tested       TEXT,
  requires_php TEXT,
  published_at TEXT NOT NULL
);
```

`activations` est ce qui te donne la **visibilité sur le partage** : une clé avec
10 domaines distincts = une clé partagée. Aucune IP, aucun user-agent.

---

## 4. Endpoints

### `POST /v1/webhook/polar` (ou `/paddle`)

Reçu du MoR. Aucune authentification utilisateur : la sécurité vient de la signature.

- Vérifier l'en-tête de signature du MoR (HMAC), refuser si horodatage > 5 min.
- **Idempotence** : insérer `event.id` dans `events` ; si déjà présent → `200` sans rien faire.
- Sur `subscription.created` / `order.paid` :
  1. Ne **pas** faire confiance au montant du payload : re-lire l'abonnement via l'API du MoR.
  2. Créer la ligne `licenses` (uuid, email, plan, sites, domain, expires).
  3. Signer la clé (§1.1) et l'envoyer par email.
- Sur `subscription.cancelled` / `expired` → `status='revoked'` + entrée dans la CRL.
- Répondre `200` vite ; le travail lourd (email) part en file.

### `POST /v1/activate`

Appelé par le plugin, une fois par 24 h maximum.

```json
{ "key": "<payload>.<signature>", "domain": "exemple.fr", "plugin_version": "0.2.0" }
```

Réponse `200` :

```json
{ "valid": true, "plan": "solo", "expires": "2027-10-29", "next_update": "2026-10-30T12:00:00Z" }
```

- Vérifier la signature **serveur aussi** (on a la clé publique sous la main).
- Refuser si `status != active` ou si `domain` ≠ domaine de la licence.
- `UPSERT` dans `activations` (`last_seen` mis à jour).
- Rate limit : 10 req/min par clé, 60/h par IP.
- Codes : `403` licence révoquée, `404` inconnue, `409` domaine non autorisé, `429` trop d'appels.

### `GET /v1/crl`

CRL signée (§1.2). `Cache-Control: public, max-age=3600`, `ETag`.

### `GET /v1/updates/rgaa-audit`

Manifeste signé (§1.3). `?key=…` optionnel : si fourni et invalide, renvoyer `403`.

### `GET /v1/download/{version}.zip?key=…`

Sert le ZIP depuis `releases.zip_path`, après vérification de la licence.
`Content-Type: application/zip`, `Content-Length`, `ETag`.

### CLI (pas d'admin web au début)

```bash
node cli.js issue --email client@exemple.fr --plan solo --sites 1 \
                  --domain https://exemple.fr --expires 2027-10-29
# → imprime la clé signée

node cli.js revoke --id <uuid> --reason refund
node cli.js publish --zip ./rgaa-audit-0.2.0.zip --version 0.2.0 \
                    --requires 6.5 --tested 6.8 --requires-php 8.1
node cli.js list --shared          # clés actives sur > 1 domaine
```

`list --shared` est ton tableau de bord du partage. C'est suffisant pour démarrer.

---

## 5. Flux complets

**Achat**
1. Client paie sur Polar/Paddle.
2. Webhook → création licence → clé signée → email.
3. Client colle la clé dans *RGAA Audit → Réglages*.
4. Le plugin vérifie **localement** (signature + domaine + expiration). Aucun appel réseau.

**Activation (opt-in)**
1. Cron quotidien → `POST /v1/activate`.
2. Le serveur enregistre le domaine, renvoie l'état.
3. Le plugin met en cache 24 h.

**Mise à jour**
1. WordPress interroge `GET /v1/updates/rgaa-audit`.
2. Le plugin compare les versions, vérifie la signature.
3. Téléchargement du ZIP, vérification du `sha256`, installation.

**Révocation**
1. Remboursement / impayé → `status='revoked'` → présente dans la CRL.
2. Le plugin récupère la CRL (24 h), vérifie la signature, coupe les fonctions pro.
3. **Jamais** de coupure immédiate : le plugin garde la dernière CRL connue et applique
   une grâce de 7 jours si le serveur est injoignable.

---

## 6. Sécurité

| Risque | Mesure |
|---|---|
| Fuite de la clé privée | fichier `0600` hors webroot, monté en lecture seule, jamais loggé ; sauvegarde chiffrée hors ligne ; plan B = régénérer la paire |
| Webhook forgé | vérification de la signature du MoR + fenêtre de 5 min |
| Rejeu de webhook | table `events`, `id` unique |
| Montant falsifié | re-lire l'abonnement via l'API du MoR, ne jamais se fier au payload |
| Abus de `/activate` | rate limit par clé et par IP, refus silencieux au-delà |
| CRL falsifiée | signature obligatoire, vérifiée côté plugin |
| Rejeu de CRL ancienne | `next_update` + refus d'une CRL plus vieille que la dernière vue |
| ZIP altéré | `sha256` dans le manifeste signé |
| Secrets dans git | `.env` en `0600`, `.gitignore`, jamais de secret dans une image Docker |

**Ce qui n'est pas défendable :** quelqu'un qui modifie le PHP du plugin. Aucune
protection hors ligne ne l'arrête. Ne construis pas le produit autour de ça.

---

## 7. RGPD

- Données stockées : email (exécution du contrat), domaine (intérêt légitime :
  application de la licence), version du plugin. **Pas d'IP, pas de user-agent.**
- Rétention : licence active + 3 ans (obligations comptables) ; `events` purgés à 90 jours.
- Le MoR est sous-traitant : à mentionner dans la politique de confidentialité.
- Le plugin doit afficher une case **opt-in** avant le premier appel réseau, avec un
  lien vers la politique de confidentialité.

---

## 8. Ops

- **TLS** : Caddy + Let's Encrypt automatique. HSTS. Seul 443 exposé.
- **Sauvegardes** : SQLite quotidien (`sqlite3 .backup`) + clé privée chiffrée hors NAS.
  **Tester la restauration** une fois avant la première vente.
- **Santé** : `GET /healthz` → `{ ok: true, db: true }`, surveillé de l'extérieur.
- **Logs** : JSON sur stdout, sans email ni clé.
- **Mises à jour** : image épinglée par digest, redéploiement manuel.
- **Domaine** : un seul suffit (`api.` et `updates.` en sous-domaines du même).

---

## 9. Plan de test (sans le plugin)

1. **Signature** : générer une clé avec le CLI, la vérifier avec
   `openssl dgst -sha256 -verify public.pem -signature <sig> <raw>` → doit répondre `Verified OK`.
2. **Bout en bout plugin** : coller la clé dans un WordPress de test (wp-now), vérifier
   qu'elle passe en `pro` ; changer le domaine dans le payload → doit être refusée.
3. **CRL** : révoquer une licence, vérifier que le plugin retombe en gratuit au
   prochain rafraîchissement, et qu'une CRL rejouée est ignorée.
4. **Webhook** : POST signé valide → licence créée + email ; même `id` rejoué → une seule licence.
5. **MAJ** : publier un ZIP, vérifier que WordPress propose la mise à jour, et qu'un
   ZIP dont le `sha256` ne correspond pas est rejeté.

---

## 10. Ce que le serveur ne doit PAS faire

- Bloquer le site du client si le serveur est injoignable.
- Vérifier la licence à chaque requête HTTP du site.
- Envoyer des données sans consentement explicite.
- Exposer un endpoint public qui signe des clés.
- Stocker des IP ou des user-agents.
- Servir un ZIP non signé.

---

## 11. Ordre d'implémentation

1. **DB + CLI `issue` + signature** → testable tout de suite avec le plugin, sans MoR.
2. **CRL + rafraîchissement côté plugin.**
3. **Webhook MoR + email transactionnel.**
4. **Endpoint de MAJ + ZIP signé + client de MAJ dans le plugin.**
5. **`/activate` + `list --shared`** (la visibilité sur le partage).

Les étapes 1 et 2 se font sans compte MoR ni domaine public : c'est le meilleur point
de départ, et ça valide la crypto avant d'engager quoi que ce soit.

---

## 12. Ce que le plugin doit ajouter (côté client)

Pour que le contrat soit complet, le plugin devra :

- `license_id` et `issued_at` dans le payload signé (nécessaire pour révoquer une clé précise).
- `RgaaAudit_License::refresh_crl()` appelé par un cron quotidien, avec cache et mode dégradé.
- Un client de mise à jour (`pre_set_site_transient_update_plugins` + `plugins_api`).
- Un réglage **opt-in** « vérification en ligne » (désactivé par défaut).
- L'appel `POST /v1/activate` dans le même cron que la CRL.

Tant que ces points ne sont pas faits, le serveur peut exister et être testé à la main
(étapes 1 et 2) sans rien casser côté plugin.
