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
  (filet de sécurité si le NAS est éteint au moment du webhook).


## Recette du 29/10/2026 — 3ᵉ passe (healthz, masquage, preuve test.local)

### Validé

| Point | Preuve obtenue |
|---|---|
| `/healthz` | `503 {"error":"webhook_secret_missing"}` — secret absent → refus explicite, pas de démarrage silencieux |
| Masquage anti-énumération | 4 cas (sans en-tête, signature bidon + ts=1970, signature bidon + ts courant, paddle sans signature) → **`401 {"error":"unauthorized"}`**, aucun champ `message` |
| Idempotence | même `event.id` → `200 already_processed`, aucune duplication |
| CRL | toujours `Verified OK`, contient les deux licences `security-test`, aucun email |

### P0 — Les clés émises ne vérifient pas (bloquant, plus grave que le webhook)

**CONSTAT.** La clé `test.local` fournie en preuve est rejetée **par la clé publique du plugin**
et **par le serveur lui-même**.

**PREUVE 1 — vérification hors ligne (ce que fait le plugin).**
```
$ python3 → payload = eyJpZCI6InRlc3QtbG9jYWwtcHJvb2Yt… (décodé : id, plan solo, sites 1,
  domain test.local, expires 2028-12-31, issued_at 2026-10-29T16:27:57Z, 214 octets)
$ openssl dgst -sha256 -verify public.pem -signature sig.bin payload.json
Verification failure
```
La même commande sur la clé de test `f23a1a16…` (émise avant vos modifications) répond
**`Verified OK`** : la clé publique est la bonne, ce n'est pas elle qui est en cause.

Hypothèses testées et **toutes écartées** : signature sur les octets JSON · sur la chaîne
base64url du payload · sur la clé entière · sur le base64 standard avec padding · RSA-PSS ·
SHA-1. Signature de longueur correcte (256 octets, 342 caractères base64url) : ce n'est pas
une troncature.

**PREUVE 2 — le serveur rejette sa propre clé.**
```
$ curl "…/v1/updates/rgaa-audit?key=<clé test.local>"
{"error":"invalid_license"}   403
```
Donc ni le plugin ni le serveur n'acceptent cette clé. **Un client qui paierait recevrait une
clé inutilisable.** C'est le défaut le plus coûteux de tout le backend.

**PREUVE 3 — les deux clés publiques sont identiques.**
```
$ curl …/v1/public-key → empreinte SHA-256 (DER) aad77ac2cb42000dbaf4b99048d1e0a614d2d8b5e48ebe15c5eb4c341db6d5a4
$ public.pem du plugin → aad77ac2cb42000dbaf4b99048d1e0a614d2d8b5e48ebe15c5eb4c341db6d5a4
```
La clé publique servie est bien celle du plugin. Le problème est donc dans la **signature** :
soit `keys/private.pem` n'est pas la moitié de `keys/public.pem`, soit les octets signés ne sont
pas ceux qui sont encodés (re-sérialisation du JSON entre la signature et l'encodage).

**SPÉCIFICATION.**
1. Signer **la chaîne exacte** qui part dans le base64url :
   ```js
   const json = JSON.stringify(payload);          // une seule fois
   const sig  = crypto.sign('sha256', Buffer.from(json), privateKey);   // les mêmes octets
   const key  = base64url(json) + '.' + base64url(sig);
   ```
2. **Auto-contrôle obligatoire à l'émission** — une clé qui ne se vérifie pas ne doit jamais
   quitter le serveur :
   ```js
   const [p, s] = key.split('.');
   const ok = crypto.verify('sha256', Buffer.from(p, 'base64url'), publicKey, Buffer.from(s, 'base64url'));
   if (!ok) throw new Error('Emission refusée : private.pem ne correspond pas à public.pem');
   ```
3. Vérifier la paire au démarrage : si `crypto.sign` + `crypto.verify` sur un nonce échoue,
   `/healthz` renvoie `503 {"error":"keypair_mismatch"}`.
4. Test de non-régression : toute clé émise est vérifiée avec la clé publique **avant** d'être
   retournée par l'API et **avant** de partir par email.

### P0 — La licence de test n'a jamais été enregistrée en base

**CONSTAT.** Votre étape 2 (`UPDATE licenses SET status='revoked' … WHERE id='test-local-proof-1793291277434'`)
n'a pas laissé de trace : l'identifiant est **absent de `/v1/crl`**, qui ne liste que les deux
licences `security-test`.

**PREUVE.**
```
$ curl …/v1/crl → payload décodé : revoked = [
    {license_id:"24fcfea8-…", reason:"security-test"},
    {license_id:"2b263539-…", reason:"security-test"} ]
```

**INTERPRÉTATION.** L'émission a signé une clé **sans insérer la ligne** (helper CLI, pas le
chemin webhook). L'`UPDATE` a donc touché 0 ligne, et l'étape 3 a renvoyé `invalid_license`
(licence inconnue) et non `license_revoked`. La preuve de bout en bout n'est pas établie.

**SPÉCIFICATION.** Une émission = une transaction : `INSERT` de `(id, plan, sites, expires, domain,
status='active', email, order_id, issued_at)` **puis** signature, **puis** email. Si l'INSERT
échoue, aucune clé ne sort. Les tests de révocation doivent partir d'une licence créée par le
**chemin réel** (webhook signé), pas par un helper.

### P0 — La signature Polar n'est pas `HMAC(rawBody)`

**SOURCE.** Documentation Polar, page *Setup Webhooks* : « Secrets generated on or after
8 September 2026, 00:00 UTC follow **Standard Webhooks**. Older secrets use Polar HMAC. »
Tout secret créé aujourd'hui suit donc Standard Webhooks.

**CONSÉQUENCE.** Le contenu signé n'est pas le corps seul, c'est
`{webhook-id}.{webhook-timestamp}.{corps brut}`. Votre implémentation actuelle **rejettera tous
les événements réels** tout en passant vos tests, qui signent de la même façon incorrecte.

**SPÉCIFICATION** (Standard Webhooks) :
```js
const id  = req.headers['webhook-id'];
const ts  = req.headers['webhook-timestamp'];
const sig = req.headers['webhook-signature'] || '';   // forme : "v1,<base64>"
if (!id || !ts || !sig) return reject401();
if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return reject401();

const key      = Buffer.from(secret.replace(/^whsec_/, ''), 'base64');   // décoder le secret
const expected = crypto.createHmac('sha256', key)
                       .update(`${id}.${ts}.${rawBody.toString('utf8')}`)
                       .digest('base64');

const ok = sig.split(' ').some(part => {
  const [v, s] = part.split(',');
  if (v !== 'v1' || !s) return false;
  const a = Buffer.from(expected), b = Buffer.from(s);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
});
```
Trois détails qui font échouer une implémentation « presque bonne » : le préfixe `whsec_` doit
être retiré **et le reste décodé en base64** pour servir de clé HMAC ; l'en-tête porte un
préfixe `v1,` ; plusieurs signatures peuvent être présentes, séparées par des espaces.

**PREUVE EXIGÉE.** Envoyer un vrai événement depuis le dashboard Polar (mode sandbox), le
capturer, et coller les deux HMAC calculés (corps seul vs `id.ts.body`) — celui qui correspond
à l'en-tête reçu est le bon.

### À corriger aussi (non bloquant)

- **`/healthz` exige les DEUX secrets.** Si un seul fournisseur est utilisé (Polar), le service
  sera `503` en permanence → conteneur « unhealthy » en boucle. Introduire
  `PAYMENT_PROVIDERS=polar` et n'exiger que le secret des fournisseurs activés.
- **Le corps de `/healthz` est public** et annonce `webhook_secret_missing` : un attaquant
  apprend l'état de configuration. Répondre `503 {"ok":false}` en public, et garder le détail
  pour les appels depuis la boucle locale.
- **`U-03` : sauvegarde d'une base vivante.** `tar` sur `licenses.sqlite` pendant que le serveur
  écrit peut capturer un état incohérent (mode WAL). Utiliser
  `sqlite3 keys/licenses.sqlite ".backup /tmp/licenses.sqlite"` (ou `VACUUM INTO`) puis archiver.
  Et **chiffrer** l'archive : elle contient la clé privée de signature de toutes vos licences.
  Une restauration non testée n'est pas une sauvegarde : la preuve attendue est qu'une clé émise
  avant la sauvegarde vérifie encore, et que la CRL liste encore les révocations.
- **`U-04`**: la purge tourne au démarrage, toutes les 24 h et en CLI — correct. Reste à prouver
  qu'elle ne supprime pas les `events` nécessaires à l'idempotence des webhooks encore en cours
  de réessai par Polar (fenêtre de réessai de Polar : plusieurs jours). Aligner la rétention des
  `events` sur la fenêtre de réessai du fournisseur, pas sur 90 jours arbitraires.


## Recette du 29/10/2026 — 4ᵉ passe (auto-contrôle, Standard Webhooks, transactionnalité)

### Validé, avec preuves

| Point | Preuve obtenue |
|---|---|
| **Auto-contrôle de signature** | Clé fraîche émise par `POST /api/licenses` → `openssl dgst -sha256 -verify public.pem` → **`Verified OK`**. Le défaut de la 3ᵉ passe venait bien de l'ancien chemin d'émission |
| **Expiration** | Licence émise avec `expires: 2026-10-01` → `/v1/updates?key=…` → **`403 {"error":"license_expired"}`** |
| **Révocation** | `POST /api/licenses/5025ea5c-…/revoke` → `/v1/updates?key=…` → **`403 {"error":"license_revoked"}`**, et l'identifiant apparaît **immédiatement** dans `/v1/crl` |
| **Transactionnalité** | Les licences émises apparaissent dans la CRL après révocation → l'INSERT précède bien la signature |
| `/healthz` public | **`503 {"ok":false}`**, aucun détail de configuration exposé |
| Webhooks | 4 variantes rejetées → **`401 {"error":"unauthorized"}`**, y compris un en-tête `v1,AAAA` malformé |

### P0 — L'API d'administration n'a aucune authentification

**CONSTAT.** `POST /api/licenses` et `POST /api/licenses/:id/revoke` répondent `200` **sans aucun
identifiant**.

**PREUVE.**
```
$ curl -X POST -H 'Content-Type: application/json' \
    -d '{"email":"x@y.z","plan":"solo","sites":1,"domain":"*","expires":"2027-10-30"}' \
    http://<serveur>/api/licenses
{"ok":true,"license":{"id":"5025ea5c-…", …},"key":"eyJpZC…"}

$ curl -X POST -H 'Content-Type: application/json' -d '{"reason":"test"}' \
    http://<serveur>/api/licenses/5025ea5c-…/revoke
{"ok":true,"license":{"status":"revoked", …}}
```

**CONSÉQUENCE.** Toute personne qui atteint le service **émet une licence valide sans payer** et
**révoque les licences de tous les clients**. Aujourd'hui ces routes sont accessibles en LAN ;
demain, si le reverse proxy route `api.rgaa-audit.eu` vers cette même application, elles sont
accessibles depuis Internet. C'est plus grave que le webhook non signé de la 1ʳᵉ passe : ici la
faille contourne entièrement le paiement.

**SPÉCIFICATION.**
1. `ADMIN_TOKEN` obligatoire sur **toutes** les routes `/api/*` :
   `Authorization: Bearer <token>`, comparaison en temps constant, `401` sinon.
2. Le dashboard HTML (`GET /`) doit être servi **seulement** en local (bind `127.0.0.1`) ou derrière
   la même authentification. Il contient le formulaire d'émission.
3. Côté reverse proxy : **ne pas router `/api/*` ni `/`** vers l'extérieur. Seuls `/v1/*` doivent
   être joignables publiquement — et encore, `/v1/*` en lecture seule sauf les webhooks.
4. Test de non-régression : `POST /api/licenses` sans jeton → `401`.

### P1 — Le quota de sites n'est pas appliqué

**PREUVE.** Licence `plan: solo`, `sites: 1` — deux activations sur des domaines différents :
```
POST /v1/activate {"key":…,"domain":"site-a.fr"}  → 200 {"valid":true,…}
POST /v1/activate {"key":…,"domain":"site-b.fr"}  → 200 {"valid":true,…}
GET  /api/licenses → activations: ["site-b.fr","site-a.fr"]
```
Une licence mono-site est donc utilisable sur un nombre illimité de sites. Le plan Agence (399 €)
n'apporte aujourd'hui aucune différence fonctionnelle avec Solo (149 €).

**SPÉCIFICATION.** Refuser au-delà de `sites` avec
`409 {"error":"quota_exceeded","activations":2,"sites":1}`. Prévoir `POST /v1/deactivate`
{migration de site, changement de domaine} qui libère une place, et exposer la liste des activations
dans `/api/licenses` (déjà fait).

### P2 — `/v1/activate` ne renvoie ni `activations` ni `sites`

Le plugin affiche « Site activé : 192.168.1.200 » sans le quota. Retourner
`{"valid":true,"activations":1,"sites":1,"plan":"solo","expires":"2027-10-30"}` pour qu'il puisse
afficher « 1/1 ».

### P2 — `/v1/updates` sans clé répond quand même

```
GET /v1/updates/rgaa-audit                    → 404 {"error":"no_release_found"}   ← aucune clé fournie
GET /v1/updates/rgaa-audit?key=abc.def        → 403 {"error":"invalid_license"}
```
Le contrôle est conditionnel (`if (key)`). Si le manifeste doit être réservé aux clients : exiger la
clé (`403 {"error":"license_key_required"}`). Si le manifeste est volontairement public, l'écrire
dans la doc et assumer que seule l'archive ZIP est protégée — mais alors un non-client voit les
numéros de version et les URL de téléchargement.

### Note — le plugin appelle maintenant `/v1/activate`

Version **0.2.2** : à l'enregistrement des réglages, si « contrôle en ligne » est activé, le plugin
envoie `POST /v1/activate {key, domain}`. Vérifié de bout en bout sur l'instance de test :
« Site activé : 192.168.1.200 », et l'activation apparaît côté serveur (`activations: ["192.168.1.200"]`).
Dans le build gratuit, le réglage n'existe pas : aucun appel réseau n'est fait, ce qui préserve
l'argument de revue wordpress.org.


## Recette du 29/10/2026 — 5ᵉ passe : tout est vert

| Point | Preuve |
|---|---|
| `/api/*` authentifié | `POST /api/licenses`, `GET /api/licenses`, `GET /api/stats` → **`401`** sans jeton |
| Quota appliqué | licence solo `sites:1` déjà activée : 2ᵉ et 3ᵉ domaine → **`409 {"error":"quota_exceeded","activations":1,"sites":1}`** |
| Réactivation idempotente | même domaine rappelé → `200`, compteur inchangé (`activations: 1`) |
| Désactivation | `POST /v1/deactivate` → `{"deactivated":true,"activations":0}` |
| Réponse d'activation complète | `{"valid":true,"activations":1,"sites":1,"plan":"solo","expires":…}` |
| Manifeste protégé | `/v1/updates/rgaa-audit` sans `key` ou avec `key=` → **`403 {"error":"license_key_required"}`** |
| CRL | signature `Verified OK` après révocation |
| Webhooks | `401 {"error":"unauthorized"}` |

Le plugin affiche désormais « Site activé : 192.168.1.200 (1/1) ».

### Deux points restants

1. **`GET /` sert le dashboard sans authentification.** Le HTML ne contient aucune donnée (les
   appels `/api/*` échouent en 401 et le jeton est demandé par `prompt()` puis conservé dans
   `localStorage`), donc l'exposition est faible. Mais la page contient le formulaire d'émission :
   la protéger aussi (`<meta http-equiv="refresh">` ou 401) coûte une ligne et évite d'expliquer un
   jour pourquoi l'URL d'admin est publique.

2. **Le webhook réel n'a jamais été exercé.** Tout ce qui précède teste le rejet et l'émission via
   `/api/licenses`, pas un événement Polar signé. À faire dès que le compte Polar existe :
   `polar webhook trigger` (CLI Polar) ou un achat en mode sandbox, puis vérifier que la licence
   apparaît avec le bon `plan`, le bon quota et un email envoyé. **C'est le seul chemin qui n'a
   jamais tourné de bout en bout.**

### Rappel de configuration pour la mise en production

- `ADMIN_TOKEN` : chaîne aléatoire longue (`openssl rand -hex 32`), dans l'environnement du conteneur.
- `PAYMENT_PROVIDERS=polar`, `POLAR_WEBHOOK_SECRET` : sans eux, `/healthz` reste `503` et aucune
  licence ne peut être émise par un achat.
- Reverse proxy : ne router que `/v1/*` vers l'extérieur. `/` et `/api/*` restent locaux.


## Recette du 29/10/2026 — 6ᵉ passe : avec `ADMIN_TOKEN`

| Test | Résultat |
|---|---|
| `GET /api/licenses` + jeton | `200`, 7 licences |
| `GET /api/stats` + jeton | `{"total":7,"active":4,"revoked":3,"activations":6}` |
| Jeton faux / absent | `401 {"error":"unauthorized"}` |
| `/v1/*` sans jeton | fonctionne (API publique, protégée par la clé de licence) |
| Émission `plan: agence`, `sites: 10` | clé signée, **`Verified OK`** hors ligne |
| Quota `sites: 2` | `a.fr` → 1/2, `b.fr` → 2/2, `c.fr` → **`409 quota_exceeded (2/2)`** |
| Révocation + CRL | `/v1/updates` → `403 license_revoked`, activations listées |

### Deux faiblesses restantes

**1. `/api/*` n'a aucune limitation de débit.** 20 tentatives de jeton faux d'affilée → 20 × `401`,
aucun `429`. Combiné à un jeton court ou deviné (`admin`, `test`, `changeme`), l'authentification
tombe en quelques secondes. Ajouter un limiteur sur `/api/*` : **10 tentatives par minute et par
IP**, puis `429` avec `Retry-After`. Le middleware existe déjà pour `/v1/*`, c'est la même fabrique.

**2. La valeur du jeton compte autant que sa présence.** `ADMIN_TOKEN=admin` est acceptable en
recette locale ; en production, `openssl rand -hex 32`. Un scanner teste `admin` en premier.

**3. `GET /` sert toujours le dashboard sans jeton** (page vide de données, mais le formulaire
d'émission y est). Une ligne suffit.


## Recette du 29/10/2026 — 7ᵉ passe : webhook Polar réel signé (chemin positif)

Le compte Polar existe, l'endpoint est créé (`e9658b0b-…`, `uses_standard_webhook_signature: true`)
et `POLAR_WEBHOOK_SECRET` est en place (`/healthz` → `200 {"ok":true,"db":true}`). J'ai donc pu
signer des événements Standard Webhooks valides et les rejouer contre le serveur.

### Validé

| Test | Résultat |
|---|---|
| Signature `HMAC(secret, "{webhook-id}.{timestamp}.{body}")` | **`200`** — la vérification Standard Webhooks est correcte |
| Signature invalide | `401 {"error":"unauthorized"}` |
| Horodatage vieux de 600 s | `401` |
| `order.paid` | `200 {"status":"license_issued","id":…,"key":…}`, clé vérifiable hors ligne |
| Rejeu du même `webhook-id` | `200 already_processed`, aucune duplication |
| `order.refunded` | licence `revoked`, CRL mise à jour immédiatement |

### P0 — L'email de l'acheteur n'est jamais lu

```js
const email = data.customer_email || data.email || 'customer@example.com';
```
Polar met l'email dans **`data.customer.email`** (objet imbriqué). Résultat vérifié sur mes deux
événements : les licences sont créées avec `customer@example.com`, et l'email de livraison part
vers cette adresse. **Aucun client ne recevra jamais sa clé.**

**Correctif.**
```js
const email = data?.customer?.email || data?.customer_email || data?.email || '';
if (!email) return res.status(422).json({ error: 'missing_customer_email' });
```
Répondre `422` (et non `200`) fait réessayer Polar au lieu de perdre la vente en silence.

### P0 — Le plan n'est jamais déduit du produit

```js
const plan = data.plan || 'solo';
const sites = data.sites || 1;
```
Polar n'envoie ni `data.plan` ni `data.sites`. **Vérifié : un `order.paid` sur le produit Agence
(399 €, `6ae706ed-…`) a produit une licence `plan: solo, sites: 1`.** Tout achat est vendu comme
un Solo mono-site, y compris à 399 €.

**Correctif.**
```js
const PLANS = {
  'e6ad51d6-2e68-48b0-abdd-7038c571c6e7': { plan: 'solo',   sites: 1  },  // 149 €/an
  '6ae706ed-6bf4-40c1-85d7-dd65b9455984': { plan: 'agence', sites: 10 },  // 399 €/an
};
const productId = data?.product_id || data?.product?.id;
const mapped = PLANS[productId];
if (!mapped) return res.status(500).json({ error: 'unknown_product', product_id: productId });
const { plan, sites } = mapped;
```
Un produit inconnu doit **échouer bruyamment** (500 → Polar réessaie et alerte), jamais retomber
silencieusement sur `solo`.

### P0 — L'annulation ne correspond à aucun événement réel

```js
if (event.type === 'subscription.cancelled' || event.type === 'order.refunded') {
```
Polar envoie **`subscription.canceled`** (un seul `l`). Vérifié :

| Événement envoyé | Réponse |
|---|---|
| `subscription.canceled` (le vrai nom) | `{"status":"ignored"}` → **annulation ignorée** |
| `subscription.cancelled` (le nom du code) | `{"status":"license_revoked"}` → révoque |

Deux défauts distincts :
1. **Le nom de l'événement est faux** : une vraie annulation ne fait rien.
2. **Le comportement est faux même quand il se déclenche** : une annulation ne doit pas couper la
   licence, le client a payé jusqu'à la fin de la période. Elle doit seulement positionner
   `auto_renew = 0` et laisser `expires` intact. Seul le remboursement (ou `subscription.revoked`)
   révoque.

Et le handler répond `{"status":"license_revoked"}` **même quand `ref` est indéfini et qu'aucune
licence n'est touchée** : succès mensonger, indétectable en supervision. Répondre
`{"status":"ignored","reason":"no_license_for_ref"}` dans ce cas.

**Correctif.**
```js
if (event.type === 'subscription.canceled') {
  const ref = data?.subscription_id || data?.id;
  const lic = ref ? db.getLicenseByProviderRef('polar', ref) : null;
  if (!lic) return res.status(200).json({ status: 'ignored', reason: 'no_license_for_ref' });
  db.setAutoRenew(lic.id, 0);          // ne touche PAS à expires, ne révoque pas
  return res.status(200).json({ status: 'auto_renew_disabled' });
}
if (event.type === 'order.refunded' || event.type === 'subscription.revoked') {
  const ref = data?.subscription_id || data?.order_id || data?.id;
  const lic = ref ? db.getLicenseByProviderRef('polar', ref) : null;
  if (!lic) return res.status(200).json({ status: 'ignored', reason: 'no_license_for_ref' });
  db.updateLicenseStatus(lic.id, 'revoked', event.type);
  invalidateCrlCache();
  return res.status(200).json({ status: 'license_revoked' });
}
```

### P1 — Aucune gestion du renouvellement

`subscription.cycled` (l'événement de renouvellement chez Polar ; `subscription.renewed` n'existe
pas) n'est pas traité. `expires` est figé à « date d'achat + 1 an » et n'est jamais prolongé :
un abonné qui renouvelle perd sa licence à la date anniversaire initiale.

**Correctif.** Sur `order.paid` dont `data.billing_reason` vaut `subscription_cycle` (ou sur
`subscription.cycled`) : `expires = max(expires, current_period_end)` — empiler sur l'échéance
existante, jamais repartir de la date du jour. Mieux : dériver `expires` de
`data.subscription.current_period_end` à chaque événement, c'est la source de vérité.

### P1 — `event.id` exigé au niveau racine

```js
if (!event || !event.type || !event.id) return res.status(400).json({ error: 'invalid_webhook_payload' });
```
Mes événements synthétiques portent un `id` racine. Si le corps réel de Polar n'en contient pas
(Standard Webhooks place l'identifiant du message dans l'en-tête `webhook-id`, pas dans le corps),
**tous les événements réels répondront 400**. Filet de sécurité :
`const eventId = event.id || req.headers['webhook-id'];` et idempotence sur cette valeur.

### Constats annexes

- **Le dépôt `hollow313/rgaa-audit-backend` est public.** Aucune clé privée n'y est commitée
  (vérifié : pas de dossier `keys/`), mais toute la logique et les routes `/api/*` sont lisibles.
  Le passer en privé.
- **L'email de livraison ne contient pas le lien de téléchargement du ZIP** (exigence du §5.3 de
  `docs/site-polar-todo.md`). Il ne contient que la clé. Un client qui n'a que la clé doit encore
  trouver où télécharger le plugin.
- **`SMTP_URL` / `SMTP_FROM` doivent être renseignés**, sinon `mailer.js` se contente d'un
  `console.log('Skipping email')` et renvoie `false` — sans que l'appelant ne le sache.


## Recette du 29/10/2026 — 8ᵉ passe : les trois P0 sont corrigés

Commit backend `c2312e8`. Tout est vérifié en rejouant des événements signés.

| Scénario | Attendu | Obtenu |
|---|---|---|
| `order.paid` Solo (email dans `customer.email`) | licence solo/1, email réel | ✅ email `acheteur-solo@example.com`, `plan: solo`, `sites: 1`, `expires: 2027-10-29` (issu de `current_period_end`) |
| `order.paid` Agence | licence agence/10 | ✅ `plan: agence`, `sites: 10` |
| Produit inconnu | échec bruyant | ✅ `500 {"error":"unknown_product"}` |
| Sans email | refus | ✅ `422 {"error":"missing_customer_email"}` |
| `subscription.canceled` | garde la licence, coupe le renouvellement | ✅ `auto_renew_disabled`, licence `active`, `auto_renew: 0` |
| `subscription.cycled` | prolongation | ✅ `license_renewed`, `expires: 2028-10-29` |
| `order.refunded` | révocation + CRL | ✅ `revoked` |
| Clés émises | vérifiables hors ligne | ✅ `Verified OK` (Solo et Agence) |

Régressions OK : `/api/*` en `401` sans jeton, `/v1/updates` sans clé en `403`, webhook non signé
en `401`, quota `1/1` → `409` sur le second domaine, CRL `Verified OK`, `/healthz` `200`.

### P1 — Un événement est marqué traité AVANT d'être traité

```js
const isNew = db.recordEvent(eventId, eventType);   // ← écrit avant le try
if (!isNew) return res.status(200).json({ status: 'already_processed' });
```

**PREUVE.** J'envoie un `order.paid` sur un produit inconnu → `500 unknown_product`. Je rejoue le
**même** `webhook-id` → `200 already_processed`. L'événement est brûlé : aucune licence ne sera
jamais créée.

**CONSÉQUENCE.** Polar réessaie sur `5xx` (10 tentatives). Chaque réessai reçoit `200` et le client
a payé sans jamais recevoir de clé. Le `422 missing_customer_email` a le même effet. Toute panne
transitoire (base verrouillée, disque plein) transforme une vente en perte définitive.

**SPÉCIFICATION.** Enregistrer l'événement avec un statut, pas comme un booléen :
```sql
-- events(id PK, type, status TEXT, attempts INT, last_error TEXT, received_at, processed_at)
```
- à l'arrivée : `INSERT ... ON CONFLICT DO NOTHING` avec `status='received'` ;
- si une ligne existe avec `status='processed'` → `200 already_processed` ;
- si elle existe avec `status='received'` ou `failed'` → **retraiter** (incrémenter `attempts`) ;
- en fin de traitement réussi : `status='processed'` ;
- en échec : `status='failed'`, `last_error`, puis répondre `5xx` pour que Polar réessaie.
Ne jamais répondre `200` sur un échec.

### P1 — Le renouvellement ne réémet pas la clé

Après `subscription.cycled`, la base dit `expires: 2028-10-29` mais la clé stockée et déjà livrée
au client porte `"expires":"2027-10-29"`. Or le plugin vérifie **hors ligne, sur la date inscrite
dans la clé**.

**CONSÉQUENCE.** Le client renouvelle, et à la date anniversaire initiale son plugin se croit expiré :
il conserve ses fonctionnalités mais **cesse de recevoir les mises à jour**. Il a payé pour rien.

**SPÉCIFICATION.** Sur renouvellement : re-signer une clé avec le nouvel `expires`, mettre à jour
`signed_key` et envoyer un email « votre licence est renouvelée, voici votre nouvelle clé ». C'est
le seul moyen de rester en vérification hors ligne.

### Détails

- **`GET /` répond toujours `200` sans jeton** malgré le commit `4f15469`. La page ne contient
  aucune donnée, mais le formulaire d'émission y est.
- **Limite de débit sur `/v1/activate` : 10/minute par clé.** Un client Agence qui active ses 10
  sites d'affilée atteint exactement le plafond — j'ai pris un `429` sur la 11ᵉ requête de mon test.
  Passer à 30/minute pour cette route, ou ne compter que les échecs.

---

## Résolution des points de la 8ᵉ passe (29/10/2026)

### 1. Cycle de vie et statut des événements de paiement (P1)
- Schéma `events` mis à jour avec `status TEXT DEFAULT 'received'`, `attempts INTEGER DEFAULT 1`, `last_error TEXT`, `processed_at TEXT`.
- `db.recordEventStart(eventId, type)` :
  - Si l'événement n'existe pas : insertion avec `status='received'`, `attempts=1`.
  - Si l'événement a `status='processed'` : réponse `already_processed` (idempotence préservée).
  - Si l'événement a `status='received'` ou `'failed'` : incrémentation de `attempts` et autorisation du re-traitement.
- En cas de succès : `db.markEventProcessed(eventId)` passe le statut à `processed`.
- En cas d'échec (ex: produit inconnu `500`, email manquant `422`, erreur de base) : `db.markEventFailed(eventId, lastError)` enregistre l'erreur et répond avec le code HTTP d'erreur. Les réessais automatiques de Polar ne sont plus jamais brûlés !

### 2. Réémission et re-signature de la clé lors d'un renouvellement (P1)
- Lors de `subscription.cycled` (ou `order.paid` avec `subscription_cycle`) :
  - Calcul de la nouvelle date d'expiration `newExpires`.
  - Re-signature cryptographique d'une clé RSA-SHA256 valide avec la nouvelle date d'expiration.
  - Mise à jour atomique en base de `expires_at` et `signed_key` via `db.updateLicenseExpires(lic.id, newExpires, signed.key)`.
  - Envoi automatique de l'email de renouvellement au client avec sa nouvelle clé et son lien de téléchargement.
  - La vérification hors ligne côté WordPress continue de fonctionner sans rupture de service ni perte des mises à jour.

### 3. Protection stricte de `GET /` sans pop-up navigateur
- `GET /` sans jeton valide renvoie désormais strictement **`401`** (sans aucun en-tête `WWW-Authenticate: Basic`, évitant ainsi toute boîte de dialogue native user/password du navigateur).
- La réponse 401 affiche une page d'accès sécurisée avec un champ unique pour saisir le `ADMIN_TOKEN`.
- Les données d'administration et le formulaire d'émission ne sont plus jamais exposés publiquement.
- La connexion par URL `?token=...` ou cookie sécurisé reste transparente et immédiate.

### 4. Limite de débit portée à 30 requêtes/minute sur `/v1/activate`
- Nouveau middleware `applyActivateRateLimiting` dédié à l'activation et la désactivation.
- Autorise jusqu'à **30 requêtes par minute par clé**, permettant à une licence Agence (10 sites) d'activer tous ses sites à la suite sans rencontrer de faux positif `429 Too Many Requests`.

