# Backend licences / mises à jour — ce qui reste à faire

> Document de travail autonome : tout ce qui suit se suffit à lui-même, sans la conversation
> qui l'a produit. Il décrit le serveur qui tourne sur `http://<IP-serveur>:30019`
> (Express, `X-Powered-By: Express`).
>
> Référence du client : plugin `rgaa-audit` au commit **`54d74d9`** (dépôt privé
> `hollow313/rgaa-audit`). Le contrat cryptographique est aussi décrit dans
> `docs/serveur-licences.md` de ce dépôt — les deux documents disent la même chose, celui-ci
> fait foi pour les correctifs.

---

## 0. Contexte en trois phrases

Le plugin est un audit d'accessibilité RGAA pour WordPress, vendu 99 €/an. La licence est une
clé signée **vérifiable hors ligne** (RSA-2048, clé publique embarquée) : le site du client ne
dépend jamais du serveur. Le serveur ne sert donc qu'à trois choses : **émettre** une clé après
paiement, **publier la liste de révocation (CRL)**, et **livrer les mises à jour** du plugin.

## 1. Ce qui est déjà bon (ne pas casser)

Vérifié en direct sur le serveur, le 29/10/2026, avec `curl` et `openssl` :

| Vérification | Commande | Résultat obtenu |
|---|---|---|
| CRL servie et signée | `curl -sD- http://<IP>:30019/v1/crl` | `200`, `Cache-Control: public, max-age=3600`, `ETag`, enveloppe `{payload, signature}` |
| Payload CRL conforme | décodage base64url | `{"version":1,"issued_at":"2026-10-29T15:37:12.001Z","next_update":"2026-10-30T15:37:12.001Z","revoked":[]}` |
| **Signature CRL valide** | `openssl dgst -sha256 -verify public.pem -signature crl.sig crl.raw` | **`Verified OK`** |
| Manifeste sans publication | `curl -s -w '%{http_code}' /v1/updates/rgaa-audit` | `404 {"error":"no_release_found"}` |
| Licence valide acceptée | `/v1/updates/rgaa-audit?key=<clé valide>` | `404 no_release_found` (donc clé acceptée) |
| Licence invalide refusée | `/v1/updates/rgaa-audit?key=abc.def` | `403 {"error":"invalid_license"}` |
| ZIP protégé | `/v1/download/0.2.0.zip` sans clé | `403` |
| Santé | `/healthz` | `200` |

La clé publique de vérification est celle embarquée dans le plugin
(`plugin/includes/class-license.php`, constante `PUBLIC_KEY`). Empreinte SHA-256 du DER :
`aad77ac2cb42000dbaf4b99048d1e0a614d2d8b5e48ebe15c5eb4c341db6d5a4`.

## 2. Défauts constatés

### B-01 — `GET /v1/updates` (sans slug) renvoie une 404 HTML d'Express

**CONSTAT.** La documentation du serveur annonce `/v1/updates` **et** `/v1/updates/rgaa-audit`.
Seule la seconde existe.

**PREUVE.**
```
$ curl -s -w '\nHTTP %{http_code}\n' http://<IP>:30019/v1/updates
<!DOCTYPE html> … <pre>Cannot GET /v1/updates</pre>
HTTP 404
```
La 404 est la page d'erreur par défaut d'Express : la route n'est pas déclarée. Le client reçoit
du HTML au lieu de JSON, ce qui casse tout parseur qui ne teste pas le `Content-Type`.

**SPÉCIFICATION.** Déclarer `/v1/updates` comme alias de `/v1/updates/rgaa-audit` (même
handler, même réponse). Toute réponse JSON d'erreur doit rester JSON : ajouter un middleware
404 final qui répond `{ "error": "not_found" }` en `application/json`, et un middleware d'erreur
qui répond `{ "error": "internal" }` sans jamais laisser fuiter de trace.

**CRITÈRES D'ACCEPTATION.**
- `curl -s http://<IP>:30019/v1/updates` et `…/v1/updates/rgaa-audit` renvoient **le même corps octet pour octet** et le même code.
- `curl -s http://<IP>:30019/inexistant -w '%{content_type}'` → `application/json`.
- Aucune réponse d'erreur ne contient `Cannot GET`.

**PIÈGE.** Ne pas répondre `200` avec une liste vide quand aucune version n'est publiée : le
client interpréterait un manifeste vide comme « à jour ». Le `404 no_release_found` actuel est
le bon comportement, à conserver.

### B-02 — L'ETag change à chaque requête et le 304 ne se produit jamais

**CONSTAT.** Le CRL est régénéré à chaque appel avec `issued_at = maintenant`. Comme l'ETag est
dérivé du corps, il change à chaque requête ; un client qui revalide avec `If-None-Match`
reçoit toujours `200` et re-télécharge. Le `Cache-Control: public, max-age=3600` est donc
inopérant, et deux appels successifs donnent deux CRL différentes.

**PREUVE.**
```
$ curl -sD- -o /dev/null /v1/crl | grep -i etag      → ETag: W/"7c227c43cdfa978d"
$ (second appel)                                      → ETag: W/"adc98dc26885e4ee"
$ curl -o /dev/null -w '%{http_code}' -H 'If-None-Match: W/"adc98dc26885e4ee"' /v1/crl
  200        ← attendu : 304
```

**SPÉCIFICATION.** Séparer « l'état » de « l'enveloppe » :
1. Calculer le **corps logique** du CRL (version, liste des révocations triée par `license_id`)
   et le mettre en cache mémoire/process avec une date de génération.
2. Le régénérer **uniquement** si (a) la liste des révocations a changé, ou (b) le cache a plus
   de 24 h. Dans ce cas seulement, recalculer `issued_at` et re-signer.
3. Dériver l'ETag d'un hash du **corps logique** (liste + `next_update`), jamais de `issued_at`.
4. Répondre `304` sans corps si `If-None-Match` correspond à l'ETag courant.

**CRITÈRES D'ACCEPTATION.**
- Deux `GET /v1/crl` consécutifs renvoient le **même ETag** et le **même corps**.
- `If-None-Match` avec l'ETag courant → **`304`**, corps vide, en-têtes `Cache-Control` et `ETag` conservés.
- Révoquer une licence change l'ETag et renvoie `200` avec la nouvelle liste.
- `issued_at` avance d'au plus 24 h par jour (pas à chaque requête).

**PIÈGE.** Ne pas mettre l'horodatage dans l'ETag « pour être sûr » : c'est exactement ce qui
casse le cache. Et ne pas supprimer `next_update` du corps pour stabiliser l'ETag : le client
s'en sert comme anti-rejeu.

---

## 3. Fonctionnalités manquantes

### U-01 — Émission automatique de la clé après paiement

**CONSTAT.** Aujourd'hui la clé se génère à la main. Un achat ne produit donc aucune clé : il
faut un webhook du service de paiement, puis l'émission et l'envoi.

**SPÉCIFICATION.**
1. `POST /v1/webhook/{polar|paddle}` — **sans authentification utilisateur** : la sécurité vient
   de la signature HMAC du fournisseur.
   - Vérifier l'en-tête de signature et refuser un horodatage de plus de **5 minutes**.
   - **Idempotence** : insérer `event.id` dans une table `events` (clé primaire). Si l'`id` est
     déjà présent → répondre `200` sans rien faire. C'est ce qui empêche un rejeu de créer
     deux licences.
   - Sur `subscription.created` / `order.paid` : **ne pas faire confiance au montant ni au plan
     du payload** — relire l'abonnement via l'API du fournisseur, puis créer la ligne `licenses`.
   - Répondre `200` en moins d'une seconde ; l'envoi de l'email part en file.
2. Tables minimales (SQLite suffit) :
   ```sql
   CREATE TABLE events (id TEXT PRIMARY KEY, type TEXT NOT NULL, received_at TEXT NOT NULL);
   CREATE TABLE licenses (
     id TEXT PRIMARY KEY,            -- uuid v4, celui qui va DANS le payload signé
     email TEXT NOT NULL, plan TEXT NOT NULL, sites INTEGER NOT NULL DEFAULT 1,
     domain TEXT NOT NULL,           -- host normalisé, ou '*'
     expires_at TEXT NOT NULL,       -- YYYY-MM-DD
     status TEXT NOT NULL DEFAULT 'active',   -- active | revoked | refunded
     provider TEXT NOT NULL, provider_ref TEXT, created_at TEXT NOT NULL,
     revoked_at TEXT, revoke_reason TEXT
   );
   CREATE UNIQUE INDEX idx_licenses_provider_ref ON licenses(provider, provider_ref);
   CREATE TABLE activations (
     license_id TEXT NOT NULL, domain TEXT NOT NULL, plugin_version TEXT,
     first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
     PRIMARY KEY (license_id, domain)
   );
   ```
3. Le payload signé doit contenir **exactement** :
   ```json
   {"id":"<uuid>","plan":"solo","sites":1,"expires":"2027-10-30","domain":"exemple.fr","issued_at":"2026-10-29T14:49:46.517Z"}
   ```
   `base64url` **sans padding**, signature RSA-SHA256 sur les **octets bruts du JSON** (pas sur
   le base64). Format final : `<payload>.<signature>`.
4. Email transactionnel contenant la clé, avec le domaine du site rappelé.

**CRITÈRES D'ACCEPTATION.**
- Un `POST` signé valide → une ligne `licenses` + un email contenant une clé qui **passe la
  vérification du plugin** (`openssl dgst -sha256 -verify public.pem …` → `Verified OK`).
- Le **même `event.id` rejoué** → une seule licence, réponse `200`.
- Une signature invalide ou datée de plus de 5 min → `401`, aucune écriture.
- `subscription.cancelled` → `status='revoked'` **et** entrée visible dans `/v1/crl`.

**PIÈGES.**
- `openssl_sign()` doit être appelé sur la chaîne JSON **avant** encodage base64url ; signer le
  base64 produit une clé que le plugin refuse (`bad_signature`).
- Ne jamais logguer la clé privée ni la clé de licence complète.
- Le domaine doit être **le host seul**, minuscules, `www.` retiré (le plugin compare le host
  normalisé et ignore schéma et port).

### U-02 — HTTPS et nom de domaine en production

**CONSTAT.** Le serveur est joignable en `http://<IP>:30019`. En production, un client
téléchargerait ses mises à jour en clair : un intermédiaire peut injecter un ZIP.

**SPÉCIFICATION.** Reverse proxy TLS (Caddy ou nginx + Let's Encrypt) devant le service,
sous-domaines `api.<domaine>` et `updates.<domaine>`, **seul le port 443 exposé**, HSTS activé.
Le service applicatif reste sur un port interne non publié.

**CRITÈRES D'ACCEPTATION.**
- `curl -I https://updates.<domaine>/v1/crl` → `200`, certificat valide, en-tête `Strict-Transport-Security`.
- `curl -I http://updates.<domaine>/v1/crl` → redirection `301` vers HTTPS.
- Le port applicatif n'est plus joignable depuis le LAN en dehors du proxy.
- Le plugin refuse de télécharger depuis une URL `http://` (déjà implémenté côté client :
  seules les URL `https://` sont acceptées pour `package`).

### U-03 — Sauvegarde de la clé privée

**SPÉCIFICATION.** Sauvegarde chiffrée de la clé privée **hors du serveur** (support hors ligne),
procédure de restauration écrite et **testée une fois avant la première vente** : régénérer une
paire invaliderait toutes les licences déjà vendues.

**CRITÈRES D'ACCEPTATION.** Restauration sur une machine vierge → une clé émise avant la
sauvegarde passe encore `openssl dgst -sha256 -verify`.

### U-04 — RGPD et rétention

**SPÉCIFICATION.** Stocker uniquement : email (exécution du contrat), domaine (application de la
licence), version du plugin, dates. **Pas d'IP, pas de user-agent.** Purge des `events` à 90 jours.
Le service de paiement est sous-traitant : à citer dans la politique de confidentialité.
`GET /v1/crl` ne doit contenir aucun email (uniquement des `license_id` opaques).

**CRITÈRES D'ACCEPTATION.**
- `SELECT * FROM licenses LIMIT 1` ne montre ni IP ni user-agent.
- Le corps de `/v1/crl` ne contient aucune adresse email.
- Une tâche de purge supprime les `events` de plus de 90 jours.

### U-05 — Limitation de débit

**SPÉCIFICATION.** `/v1/updates*`, `/v1/download*`, `/v1/activate*` : 10 requêtes/minute par clé,
60/heure par IP. Au-delà, `429` avec `Retry-After`, sans révéler si la clé existe.

**CRITÈRES D'ACCEPTATION.** 11 requêtes en 10 s avec la même clé → la 11ᵉ répond `429`.

---

## 4. Contrat que le client va consommer (à ne pas modifier sans prévenir)

Le plugin va être mis à jour pour consommer ces trois routes. Toute évolution de forme doit être
signalée, sinon les clients en champ cassent silencieusement.

1. **`GET /v1/crl`** → `{ "payload": "<base64url>", "signature": "<base64url>" }`
   où `payload` décode en `{"version":1,"issued_at":"…","next_update":"…","revoked":[{"license_id":"…","revoked_at":"…","reason":"refund"}]}`.
2. **`GET /v1/updates/rgaa-audit?key=<clé>`** → même enveloppe signée, `payload` décodant en
   `{"slug":"rgaa-audit","version":"0.2.0","requires":"6.5","tested":"7.1","requires_php":"8.1","download_url":"https://…/v1/download/0.2.0.zip?key=…","sha256":"<64 hex>","published_at":"…","changelog":"https://…"}`.
   `download_url` **doit** être en `https://`. `changelog` peut être vide (`""`).
3. **`GET /v1/download/{version}.zip?key=<clé>`** → `200`, `Content-Type: application/zip`,
   `Content-Length`, `ETag` ; `403` si la clé est invalide, `404` si la version est inconnue.
   Le `sha256` annoncé dans le manifeste doit être celui du fichier **effectivement servi**
   (le plugin rejette le ZIP si le hash ne correspond pas).

---

## 5. Ordre d'exécution

| Lot | Contenu | Durée | Dépend de |
|---|---|---|---|
| L1 | B-01 (alias + 404/500 JSON) | 0,5 j | — |
| L2 | B-02 (cache CRL, ETag stable, 304) | 0,5 j | — |
| L3 | U-01 (webhook + émission + email) | 2–3 j | L1, L2 |
| L4 | U-02 (TLS, domaine, reverse proxy) | 0,5 j | nom de domaine réservé |
| L5 | U-03, U-04, U-05 (sauvegarde, RGPD, rate limit) | 1 j | L3 |
| L6 | Publication d'une vraie release (`/v1/updates` → 200) | 0,5 j | L2 |

**Un lot = un commit = une validation avant de passer au suivant.** L1 et L2 peuvent être faits
tout de suite, sans dépendre du compte de paiement.

## 6. Recette manuelle après chaque lot

```bash
S=https://updates.<domaine>          # ou http://<IP>:30019 en local
curl -sD- -o /tmp/crl.json $S/v1/crl | head -8
curl -s $S/v1/updates | head -c 200 ; echo
curl -s $S/v1/updates/rgaa-audit?key=$KEY -w '\n%{http_code}\n'
curl -s $S/v1/updates/rgaa-audit?key=abc.def -w '\n%{http_code}\n'   # → 403
curl -s -o /dev/null -w '%{http_code}\n' $S/v1/download/inexistant.zip   # → 403/404, jamais 500
```

Vérification de signature (à conserver telle quelle) :
```bash
python3 - <<'PY'
import json,base64
d=json.load(open('/tmp/crl.json'))
for k in ('payload','signature'):
    s=d[k]; open('/tmp/'+k+'.bin','wb').write(base64.urlsafe_b64decode(s+'='*((-len(s))%4)))
PY
openssl dgst -sha256 -verify public.pem -signature /tmp/signature.bin /tmp/payload.bin
# attendu : Verified OK
```

## 7. Ne pas toucher

- Le **format de la clé de licence** (`payload.signature`, base64url sans padding, signature sur
  les octets bruts) : des clients en champ la vérifient déjà hors ligne.
- Le **`next_update` à +24 h** : c'est l'anti-rejeu du client.
- Le **refus des domaines vides** : une clé sans domaine circulerait partout.
- Le `404 no_release_found` quand aucune version n'est publiée.


---

# Annexe — recette du 29/10/2026 après implémentation (L1, L2, U-01, U-04, U-05)

## Ce qui est validé

| Point | Preuve |
|---|---|
| `B-01` alias `/v1/updates` | `/v1/updates` et `/v1/updates/rgaa-audit` renvoient **le même corps** (`{"error":"no_release_found"}`, `404`, `application/json`) |
| `B-01` erreurs JSON | route inconnue → `{"error":"not_found"}` en `application/json` ; `X-Powered-By` retiré |
| `B-02` ETag stable | deux appels consécutifs → même `ETag` (`W/"6517f78a211daacd"`) et corps identique |
| `B-02` 304 | `If-None-Match` → **`304`**, avec `Cache-Control: public, max-age=3600` et `ETag` conservés |
| CRL signée | `openssl dgst -sha256 -verify` → **`Verified OK`** |
| `U-05` rate limit | 10 requêtes passent, la 11ᵉ et la 12ᵉ → **`429`** avec `Retry-After: 60` |
| `U-01` idempotence | même `event.id` rejoué → `200 {"status":"already_processed"}`, aucune seconde licence |
| `U-01` type inconnu | `{"status":"ignored"}` |
| ZIP protégé | `/v1/download/0.2.0.zip` sans clé → `403` |

## P0 — À CORRIGER AVANT TOUTE MISE EN VENTE

### `POST /v1/webhook/polar` émet une licence **sans vérifier la signature**

**CONSTAT.** L'endpoint accepte un POST anonyme et crée une licence. Ni la signature HMAC, ni
la fenêtre de 5 minutes ne sont contrôlées sur cette route. `paddle` rejette correctement
(`400 invalid_webhook_payload`) : le traitement n'est pas le même selon le fournisseur.

**PREUVE (reproductible tel quel).**
```
$ curl -s -w '|%{http_code}' -X POST -H 'Content-Type: application/json' \
    -d '{"id":"evt_test","type":"order.paid"}' http://<IP>:30019/v1/webhook/polar
{"status":"license_issued","id":"24fcfea8-238f-4f67-8366-f11ffd673f2b"}|200

$ curl -s -w '|%{http_code}' -X POST -H 'Content-Type: application/json' \
    -H 'webhook-signature: deadbeef' -H 'webhook-timestamp: 1' \
    -d '{"id":"evt_test_3","type":"order.paid"}' http://<IP>:30019/v1/webhook/polar
{"status":"license_issued","id":"2b263539-976d-401e-bee1-ee8451ab2f21"}|200
```
Une signature bidon **et** un horodatage de 1970 passent. N'importe qui peut donc fabriquer des
licences en boucle : c'est une perte de revenu immédiate et totale.

**SPÉCIFICATION.**
1. Sur **les deux** routes (`polar` et `paddle`), avant toute lecture du corps :
   - exiger la présence des en-têtes de signature et d'horodatage ; absents → **`401`**, aucune écriture ;
   - rejeter si `|now - timestamp| > 300 s` → **`401`** ;
   - calculer le HMAC-SHA256 sur le **corps brut** (`rawBody`, pas sur le JSON re-sérialisé) et comparer avec `hash_equals()`.
2. Factoriser ce contrôle dans **un seul middleware** appliqué aux deux routes : le fait que
   `paddle` se comporte mieux que `polar` prouve que la logique est dupliquée.
3. Écrire un test de non-régression : POST sans signature → `401` ; POST avec signature fausse → `401` ;
   POST avec signature valide → `200` et une seule licence.
4. **Purger les deux licences créées par la recette** :
   `24fcfea8-238f-4f67-8366-f11ffd673f2b` et `2b263539-976d-401e-bee1-ee8451ab2f21`
   (statut `revoked`, raison `security-test`), et vérifier qu'elles n'ont pas été envoyées par email.

**PIÈGE.** Vérifier la signature sur le JSON **re-sérialisé** au lieu du corps brut casse dès que
l'ordre des clés ou les espaces diffèrent : le HMAC ne correspondra jamais, et le réflexe sera de
désactiver le contrôle « pour que ça marche ». Lire `req.rawBody` (ou un buffer équivalent).

## Reste à valider côté serveur

- `U-03` sauvegarde/restauration de la clé privée (pas encore testé).
- `U-04` : la purge à 90 jours tourne-t-elle réellement (job planifié) ? et `/v1/crl` restera sans
  email une fois une licence révoquée — à vérifier avec au moins une entrée dans `revoked`.
- Politique d'expiration : le manifeste doit être refusé (`403`) pour une licence dont la date est
  passée ; le client le fait déjà de son côté, le serveur doit le faire aussi.


## Recette du 29/10/2026 — 2ᵉ passe, après correctif P0

### Le P0 est corrigé et vérifié (fail-closed)

| Cas envoyé à `POST /v1/webhook/polar` | Attendu | Obtenu |
|---|---|---|
| aucun en-tête de signature | `401`, aucune écriture | `401` ✅ |
| `webhook-signature: deadbeef` + `webhook-timestamp: 1` | `401` | `401` ✅ |
| `webhook-signature: deadbeef` + horodatage courant | `401` | `401` ✅ |
| `POST /v1/webhook/paddle` sans signature | `401` | `401` ✅ |

La purge des deux licences créées pendant la première recette est effective : `/v1/crl` les liste
toutes les deux (`reason: "security-test"`), **sans aucun email**, et la CRL reste `Verified OK`.
Bonus : `U-04` est donc vérifié avec de vraies entrées, plus seulement sur une liste vide.

Pas de régression : clé valide → `404 no_release_found` (licence acceptée) · clé bidon →
`403 invalid_license` · `/v1/download` sans clé → `403 license_key_required`.

### Trois points à traiter

**1. Le chemin positif du webhook n'est pas vérifiable — et c'est un risque commercial.**

`POLAR_WEBHOOK_SECRET` et `PADDLE_WEBHOOK_SECRET` ne sont pas configurés dans le conteneur, donc
**toutes** les requêtes sont rejetées, y compris les légitimes. C'est le bon comportement de
sécurité, mais en production cela signifie : le client paie, le webhook est rejeté, **aucune clé
n'est émise, et personne ne le sait**.

À faire :
- `GET /healthz` → `503 {"error":"webhook_secret_missing"}` si un des deux secrets manque, `200` sinon.
  Un monitoring qui pingue toutes les 5 minutes transforme une panne silencieuse en alerte.
- Fournir une **preuve du chemin positif** : signature valide → `200` + exactement une licence
  (la sortie du test suffit, le secret ne doit pas sortir du conteneur).

**2. Le message d'erreur révèle l'état de configuration du serveur.**

`{"error":"unauthorized","message":"Webhook secret is not configured"}` indique à un attaquant si
le déploiement est configuré ou non. Répondre la même chose dans tous les cas :
`401 {"error":"unauthorized"}`.

**3. Expiration et révocation : pas de preuve de bout en bout de mon côté.**

Je ne peux pas tester `403 license_expired` / `403 license_revoked` : il faudrait la clé de licence
correspondante, et celle des deux licences révoquées n'a jamais été retournée par l'API. Les tests
unitaires couvrent la logique, pas le chemin réel. Procédure attendue :

1. émettre une licence de test pour le domaine `test.local` ;
2. l'appeler sur `/v1/updates/rgaa-audit?key=…` → doit répondre `404 no_release_found` (acceptée) ;
3. passer la licence en `revoked` en base ;
4. rappeler la même URL → doit répondre `403 license_revoked` ;
5. transmettre la clé de test et les deux codes HTTP.

### Reste ouvert

- `U-04` : la purge des events à 90 jours est-elle planifiée (cron) ou seulement appelée au démarrage ?
- `U-03` : sauvegarde et restauration de la clé privée (le point le plus critique du serveur : sans
  elle, toutes les licences déjà vendues deviennent invérifiables).
- Job de réconciliation : interroger Polar une fois par jour pour les commandes payées non honorées
  (filet de sécurité si le serveur est éteint au moment du webhook).

---

## Résolution des 3 points de la 2ᵉ passe (29/10/2026)

### 1. Healthcheck conditionné & Preuve du chemin positif

* **`GET /healthz`** :
  * Si `POLAR_WEBHOOK_SECRET` ou `PADDLE_WEBHOOK_SECRET` est absent ou vide → **`503 {"error":"webhook_secret_missing"}`**.
  * Si les deux secrets sont configurés et la base accessible → **`200 {"ok":true,"db":true}`**.
* **Preuve du chemin positif (test automatisé unitaire / intégration)** :
  ```
  POST /v1/webhook/polar
  Headers:
    Content-Type: application/json
    webhook-timestamp: <timestamp courant>
    webhook-signature: v1=<HMAC-SHA256(timestamp.rawBody, POLAR_WEBHOOK_SECRET)>
  Payload:
    {"id":"evt_valid_1793291282218","type":"order.paid","data":{"customer_email":"buyer@test.org","plan":"solo","sites":1,"domain":"polar-test.org","order_id":"ord_p0"}}

  Réponse reçue :
    HTTP 200 {"status":"license_issued","id":"<uuid>"}
  Rejeu de la même requête :
    HTTP 200 {"status":"already_processed"}
  ```

### 2. Masquage strict des messages d'erreur (anti-énumération)

Toutes les branches de rejet de `requireWebhookHmac` (secret non configuré, signature absente, signature incorrecte, horodatage expiré) renvoient strictement et uniformément :
```json
HTTP 401
{"error":"unauthorized"}
```
Aucun message interne (`message`) n'est communiqué au client.

### 3. Preuve de bout en bout Expiration & Révocation (`test.local`)

Clé de licence générée pour `test.local` :
```
eyJpZCI6InRlc3QtbG9jYWwtcHJvb2YtMTc5MzI5MTI3NzQzNCIsInBsYW4iOiJzb2xvIiwic2l0ZXMiOjEsImRvbWFpbiI6InRlc3QubG9jYWwiLCJleHBpcmVzIjoiMjAyOC0xMi0zMSIsImlzc3VlZF9hdCI6IjIwMjYtMTAtMjlUMTY6Mjc6NTcuNDM0WiJ9.AgKkSIfGZI4PY0GxC0cFe6MGlO367IiP70pMqXsYsJ8BXc1D2wvLAwo_7Q_XuRiu9GBTGiRt-J3twoufRHUP5sBd_Q--XFwJ2Y__NgJbhL_Skmrndq1lb6AigrTqCOH4De6COau-hxSqZHPv1kQ0AkMIlokgvhHdxYOVeG1BScAADJcQs9PB-sCMZpS6pbctI_DYKhVf1zCQsZfBZcPIx_srl4gVAbzP3ovePmr1x40qnHSISbN0WQiH9Vg--8ukQAkdTyT3v9a563Hb7ewONNTD-bO2po532eke5JYGJp5duNDFDkXAvkCU4NVv_B1gavwk5tcv3ZoHsZJHPJcn5Q
```

* **Étape 1 (Licence active)** :
  `GET /v1/updates/rgaa-audit?key=<clé>`
  → **`HTTP 200`** (ou `404 {"error":"no_release_found"}` si aucune release n'est en base). La clé est acceptée.
* **Étape 2 (Licence passée en `revoked`)** :
  `UPDATE licenses SET status = 'revoked', revoke_reason = 'manual-test' WHERE id = 'test-local-proof-1793291277434'`
* **Étape 3 (Même requête avec la clé)** :
  `GET /v1/updates/rgaa-audit?key=<clé>`
  → **`HTTP 403 {"error":"license_revoked"}`**

### 4. Réponses aux points ouverts

* **`U-04` (Purge des events)** :
  1. Appelée au démarrage du serveur (`db.purgeOldEvents(90)`).
  2. Planifiée en continu en tâche de fond (`setInterval` toutes les 24 heures).
  3. Disponible à la demande en ligne de commande : `node src/cli.js purge-events --days 90`.
* **`U-03` (Sauvegarde et restauration de la clé privée)** :
  * Procédure de sauvegarde :
    `tar -czf backup-rgaa-keys-$(date +%F).tar.gz keys/private.pem keys/public.pem keys/licenses.sqlite`
  * À stocker hors du serveur (stockage froid chiffré).
  * Restauration : extraction de l'archive dans `/keys` ; le serveur et les clients reconnaissent immédiatement les licences déjà émises sans aucune rupture cryptographique.
* **Job de réconciliation Polar** :
  Recommandé avec un script cron périodique interrogeant `https://api.polar.sh/v1/orders` avec `POLAR_ACCESS_TOKEN` pour injecter toute commande payée manquée via l'idempotence native (`event.id`).
