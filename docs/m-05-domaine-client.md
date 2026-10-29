# M-05 — Signer la clé de licence avec le domaine du client

**Destinataire : Antigravity (backend `rgaa-audit-backend`)**
**Date : 29/10/2026 — auteur : Hermes**
**Priorité : P1 — bloquant commercial, pas bloquant technique**

---

## 1. Le contexte en trois lignes

RGAA Audit est une extension WordPress payante (149 €/an Solo, 399 €/an Agence) vendue via Polar
(merchant of record). Après paiement, Polar appelle `POST /v1/webhook/polar`, le backend signe une clé
RSA contenant `{id, plan, sites, expires, domain, issued_at}` et l'envoie par email. Le plugin vérifie
cette clé **hors ligne** avec sa clé publique embarquée, et compare le `domain` du payload au host du
site.

## 2. Le défaut

Dans `src/server.js`, handler `POST /v1/webhook/polar`, branche « achat initial » :

```js
const domain = data.domain || '*';
```

**Polar n'envoie jamais `data.domain`.** Conséquence : toutes les clés vendues sont signées avec
`domain: "*"`, donc **valables sur n'importe quel site, hors ligne, sans aucune contrainte**. Le
contrôle de domaine du plugin ne s'exerce jamais sur une vente réelle.

Preuve (29/10/2026, webhook `order.paid` forgé et signé) :

```
payload décodé : {"id":"…","plan":"solo","sites":1,"expires":"2027-10-29","domain":"*",…}
```

Seul le quota d'activations (`/v1/activate`, plafonné par `sites`) limite quelque chose, et il exige
`online_check` — que le build gratuit n'active pas. Une clé Solo achetée une fois peut donc équiper
un parc entier de sites sans appeler le serveur.

## 3. Côté Polar : déjà fait

Un champ personnalisé a été créé dans l'organisation `3d976372-95dc-448c-b655-5718d372fcb3` et rendu
**obligatoire** sur les deux produits.

```
custom_field_id : 034b493d-ad22-4d9c-8274-3e2537726617
slug            : domain
type            : text          (min_length 4, max_length 253)
label           : Domaine du site à licencier
aide            : Le domaine exact du site WordPress, sans https:// ni www. Exemple : mon-site.fr
produits        : RGAA Audit — Solo    e6ad51d6-2e68-48b0-abdd-7038c571c6e7  (required: true)
                  RGAA Audit — Agence  6ae706ed-6bf4-40c1-85d7-dd65b9455984  (required: true)
```

Vérifié sur la page de paiement réelle (`buy.polar.sh/polar_cl_XaYo2DqiioQ2YDmtNZ8B5DoM2tgxVIt9Z7rMy1jBcCa`) :
le champ s'affiche. Le client saisit donc son domaine **au moment de payer**, et Polar le renvoie dans
l'événement de commande sous `custom_field_data`, indexé par le slug.

Forme attendue dans le payload webhook :

```json
"custom_field_data": { "domain": "mon-site.fr" }
```

> Si la forme réelle diffère (objet vs tableau, clé `custom_field_data` vs `custom_fields`), **se fier à
> un événement Polar réel** capturé depuis le dashboard (section Sales → commande → Custom Fields), pas
> à cette doc. Le champ est nouveau : c'est le premier événement qui fera foi.

## 4. Ce qu'il faut changer

### 4.1 Lire le champ, avec une normalisation défensive

Le client tape ce qu'il veut : `https://`, `www.`, un chemin, des majuscules, un espace final.

```js
const rawDomain = data?.custom_field_data?.domain || data?.domain || '';
const domain    = rawDomain ? normalizeDomain(rawDomain) : '*';
```

`normalizeDomain()` existe déjà (elle retire schéma, `www.`, port et chemin). **Vérifier qu'elle gère
aussi** : espaces en début/fin, valeur vide, chaîne sans point (`monsite`), et qu'elle ne renvoie pas
une chaîne vide pour une entrée invalide.

### 4.2 Refuser une commande **Polar** sans domaine exploitable

C'est le cœur du correctif : sans ça, le champ reste décoratif.

```js
if (!domain || domain === '*') {
  db.markEventFailed(eventId, 'missing_domain');
  return res.status(422).json({ error: 'missing_domain' });
}
```

- **`422`, pas `500`** : Polar réessaie sur `5xx`. Un événement sans domaine ne sera jamais réparé par
  un réessai — il doit atterrir en `failed` et être traité à la main.
- **Aucune licence créée** dans ce cas : ni en base, ni signée, ni emailée.
- Le motif doit être visible dans `/api/stats` (compteur d'événements en échec) pour qu'un achat non
  livré se voie sans aller fouiller la base.

### 4.3 Garder `*` pour l'émission manuelle

`POST /api/licenses` doit continuer d'accepter un `domain` explicite, **y compris `*`** (tests, gestes
commerciaux, licences de démonstration). Le refus du 4.2 ne concerne **que** le chemin webhook Polar.

Les clés déjà vendues avec `*` **restent valides** : ne rien révoquer, ne rien réémettre.

### 4.4 Tracer la valeur brute

Ajouter une colonne `domain_raw` (texte libre) à côté de `domain` (normalisé) :

```
domain      = 'mon-site.fr'      ← ce qui est signé dans la clé
domain_raw  = 'Mon-Site.FR'      ← ce que le client a réellement tapé
```

En cas de contestation ou d'erreur de saisie (`monsite` sans `.fr`), le diagnostic se fait en une
requête au lieu d'un échange de mails. Migration SQLite : `ALTER TABLE licenses ADD COLUMN domain_raw TEXT`.

### 4.5 Le renouvellement conserve le domaine existant

Branche `subscription.cycled` / `order.paid` avec `billing_reason = 'subscription_cycle'` : elle
**re-signe la clé avec le domaine de la licence déjà en base**, jamais avec une nouvelle saisie ni
avec `*`. Le client renouvelle sans repasser par le formulaire de paiement ; sa clé doit rester liée
au même domaine.

## 5. Critères d'acceptation

Chaque point se vérifie avec un webhook `order.paid` forgé et signé (le secret de l'endpoint permet de
signer sans passer par Polar) :

```bash
SECRET=$(cat /data/.polar/webhook_secret | sed 's/^whsec_//')
TS=$(date +%s); WID="msg_test_$TS"
BODY='{"type":"order.paid","data":{"id":"order-test'$TS'","billing_reason":"purchase","customer":{"email":"loic.huon.automation@gmail.com"},"product_id":"e6ad51d6-2e68-48b0-abdd-7038c571c6e7","custom_field_data":{"domain":"Mon-Site.FR"}}}'
SIG=$(python3 -c "
import hmac,hashlib,base64,sys
k=base64.b64decode('$SECRET')
print(base64.b64encode(hmac.new(k,'$WID.$TS.'+sys.argv[1],hashlib.sha256).digest()).decode())" "$BODY")
curl -s -X POST http://192.168.1.200:30019/v1/webhook/polar \
  -H 'Content-Type: application/json' \
  -H "webhook-id: $WID" -H "webhook-timestamp: $TS" -H "webhook-signature: v1,$SIG" \
  --data-binary "$BODY"
```

| # | Entrée | Attendu |
|---|---|---|
| 1 | `order.paid` **sans** `custom_field_data.domain` | `422 {"error":"missing_domain"}`, aucune licence créée, événement `failed`, rejeu du même `webhook-id` → `422` (pas `already_processed`) |
| 2 | `domain: "Mon-Site.FR"` | `200 license_issued`, payload `"domain":"mon-site.fr"`, base `domain='mon-site.fr'`, `domain_raw='Mon-Site.FR'` |
| 3 | `domain: "https://www.mon-site.fr/contact"` | `"domain":"mon-site.fr"` |
| 4 | `domain: " mon-site.fr "` (espaces) | `"domain":"mon-site.fr"` |
| 5 | `domain: ""` ou `"   "` | `422 missing_domain` |
| 6 | `POST /api/licenses` avec `domain: "*"` | `200`, clé `*` (émission manuelle préservée) |
| 7 | `subscription.cycled` sur une licence `mon-site.fr` | clé re-signée, `expires` prolongé, **`domain` inchangé** |
| 8 | Clé du point 2 collée dans un WordPress dont le host diffère | plugin : refus `no_domain`, retour en version gratuite |
| 9 | Clé du point 2 collée sur `mon-site.fr` | « Plan solo actif », grille et déclaration débloquées |
| 10 | Non-régression M-04 | l'email contient toujours `https://api.rgaa-audit.eu/v1/download/<version>.zip?key=…` et ce lien renvoie `200` |

## 6. Ce qu'il ne faut pas faire

- **Ne pas** garder `data.domain` en premier recours au-dessus de `custom_field_data` : ce champ
  n'existe pas chez Polar et masquerait un bug de lecture.
- **Ne pas** répondre `500` sur `missing_domain` : Polar réessaierait indéfiniment une commande qui ne
  peut pas aboutir.
- **Ne pas** révoquer ni réémettre les licences `*` déjà en base.
- **Ne pas** exiger un domaine sur `POST /api/licenses` : l'émission manuelle doit rester possible.

## 7. Après livraison

1. Rejouer les 10 critères ci-dessus et me transmettre les codes HTTP + un payload décodé du point 2.
2. Contrôler que `GET /v1/updates/rgaa-audit?key=<clé du point 2>` répond `200` (une clé liée à un
   domaine doit rester acceptée par le manifeste).
3. Un achat réel en sandbox Polar pour vérifier que le champ saisi au checkout arrive bien dans
   l'événement — c'est le seul point que la forge ne prouve pas.
