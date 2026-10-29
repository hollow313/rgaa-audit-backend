# Backend de licences — dernières modifications avant la mise en vente

**Référence** : commit backend `5fba070`. Vérifier avec `git log -1` avant d'appliquer : les numéros
de ligne bougent, les noms de fonction non.

**État validé** (ne pas y retoucher) : signature Standard Webhooks, rejet uniforme en `401`, cycle de
vie des événements (`received|processed|failed` + `attempts`), mapping produit → plan, email imbriqué
`data.customer.email`, annulation qui coupe seulement le renouvellement, prolongation sur
`subscription.cycled` avec **re-signature de la clé**, quota `409`, désactivation, `GET /` et
`/api/*` derrière `ADMIN_TOKEN`, CRL signée sans donnée personnelle.

Il reste deux chantiers. Le premier bloque la vente.

---

## M-01 (P0) — La livraison email échoue et le webhook répond `200`

### Constat

`SMTP_URL` et `SMTP_FROM` sont désormais renseignés dans le conteneur, mais aucun email n'arrive.

**Preuve, deux fois de suite.** J'envoie un `order.paid` correctement signé pour le produit Solo
(`e6ad51d6-…`) avec l'adresse réelle `loic.huon.automation@gmail.com`. Réponse du serveur :

```
HTTP 200 {"status":"license_issued","id":"9c1a0871-34f7-42bd-bd79-714955c82737","key":"eyJpZC…"}
```

Trente secondes plus tard, la boîte ne contient aucun message de RGAA Audit.

**Cause immédiate** : la boîte `licence@rgaa-audit.eu` n'existe pas encore côté OVH (le domaine
n'est pas enregistré). L'authentification SMTP échoue donc — mais les serveurs OVH sont joignables
depuis le NAS (`smtp.mail.ovh.net:465` répond `220`), ce n'est pas un problème réseau.

**Cause de fond, dans `src/server.js`** :

```js
sendLicenseEmail({ … }).catch(err => console.error(`[webhook] Mail error: ${err.message}`));
…
return res.status(200).json({ status: 'license_issued', id: licenseId, key: signed.key });
```

L'échec est avalé par un `catch` et le handler répond `200`. Polar considère la livraison réussie,
ne réessaie pas, la licence existe en base, et le client n'a rien reçu. **C'est exactement le
scénario qui produit un remboursement et une réclamation, sans aucune trace.**

### Spécification

**1. Colonnes de suivi sur `licenses`**

```sql
ALTER TABLE licenses ADD COLUMN emailed_at TEXT;
ALTER TABLE licenses ADD COLUMN mail_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE licenses ADD COLUMN mail_last_error TEXT;
```

**2. `/healthz` expose l'état du mailer**

```json
{"ok": true, "db": true, "mail": true}
```

`mail` vaut `false` si `SMTP_URL` ou `SMTP_FROM` est vide, ou si la dernière tentative d'envoi a
échoué pour une raison d'authentification/connexion. **Ne pas renvoyer `503` pour autant** : un
redémarrage du conteneur ne répare pas des identifiants SMTP, et un healthcheck qui boucle met le
service par terre.

**3. Ne jamais répondre `200` sur un échec d'envoi**

Ordre attendu dans le handler :

1. `INSERT` de la licence (déjà fait), `emailed_at = NULL` ;
2. tentative d'envoi ;
3. en cas de succès : `emailed_at = now`, `status = 'processed'`, réponse `200` ;
4. en cas d'échec : `mail_attempts++`, `mail_last_error`, événement en `status='failed'`,
   réponse **`5xx`** — Polar réessaie jusqu'à 10 fois, c'est exactement ce qu'on veut.

**4. Idempotence du réessai**

Polar va rejouer l'événement. Au second passage, la licence existe déjà
(`provider_ref = data.subscription_id | data.order_id`). Il faut donc :

- retrouver la licence par `provider_ref` **avant** d'en créer une nouvelle ;
- si elle existe et `emailed_at IS NULL` → renvoyer uniquement l'email, pas de seconde licence ;
- si elle existe et `emailed_at IS NOT NULL` → `200 already_processed`.

**Critère d'acceptation** : deux POST successifs du même `webhook-id` avec des identifiants SMTP
cassés produisent **une seule licence**, `mail_attempts = 2`, `emailed_at` nul, et deux réponses `5xx`.

**5. Contenu de l'email**

Le message actuel ne contient que la clé. Il doit aussi contenir le lien de téléchargement, sinon
un client qui a perdu le ZIP n'a aucun moyen de le récupérer :

```js
const downloadUrl = `${PUBLIC_BASE_URL}/v1/download/${version}.zip?key=${encodeURIComponent(key)}`;
```

et une version `html` en plus de `text` dans `sendMail`. Rappel : la clé doit rester **en clair dans
le corps**, pas en pièce jointe.

**6. `POST /v1/resend-key`**

Protégé par `ADMIN_TOKEN`. Corps `{"license_id": "…"}` ou `{"email": "…"}`. Renvoie un `200` avec
`{"sent": true}` ou `{"sent": false, "error": "…"}`. Indispensable : le premier réflexe d'un client
qui n'a rien reçu est d'écrire au support.

**7. `/api/stats`** doit exposer `"emails_pending"` et `"emails_failed"` : sans ce chiffre, une file
d'envoi cassée reste invisible.

---

## M-02 — Pouvoir supprimer une licence

Le tableau de bord ne permet que de créer et de révoquer. Après une recette, la liste se remplit de
licences de test et il faut supprimer `licenses.sqlite` pour les faire disparaître — ce qui efface
aussi les journaux d'événements et casse la traçabilité.

**Routes à ajouter** (toutes derrière `ADMIN_TOKEN`) :

| Route | Effet |
|---|---|
| `DELETE /api/licenses/:id` | supprime la licence et ses activations, répond `204` |
| `POST /api/licenses/purge` | corps `{"confirm": "PURGE", "filter": "test\|revoked\|all"}` |

- `filter: "test"` → les emails en `@example.com`, `@test.local` et les licences créées via
  `/api/licenses` sans `provider_ref` ;
- `filter: "revoked"` → statut `revoked` uniquement ;
- `filter: "all"` → tout.

Après une suppression : **invalider le cache CRL** (sinon un identifiant supprimé reste listé dans
`/v1/crl` jusqu'à l'expiration du cache, et une clé supprimée continuerait d'être refusée comme
« révoquée » au lieu de « inconnue »).

Ajouter un bouton « Supprimer » par ligne et un bouton « Purger les tests » dans le dashboard, avec
une confirmation par saisie du mot `PURGE` — pas un simple `confirm()`.

**Critère d'acceptation** : après `purge {"filter":"test"}`, `/api/stats` renvoie `total: 0`, la liste
est vide, et `/v1/updates` avec une clé supprimée répond `403 invalid_license` (et non `license_revoked`).

---

## Ce qu'il ne faut pas faire

- **Ne pas toucher à `keys/private.pem` ni `keys/public.pem`.** Ce sont eux qui signent les licences ;
  les régénérer invalide toutes les clés déjà émises et oblige à reconstruire le plugin.
- **Ne pas répondre `200` « pour ne pas faire échouer Polar »** sur un envoi d'email raté : c'est
  précisément ce qui perd la vente en silence.
- **Ne pas déduire l'email depuis `data.email`** ni `data.customer_email` : la seule source est
  `data.customer.email`, tout le reste est un repli qui produit `customer@example.com`.
- **Ne pas passer le plan à `solo` par défaut** sur un `product_id` inconnu : `500 unknown_product`
  est le bon comportement, il rend l'oubli visible dès le premier achat.

---

## Recette attendue en retour

Coller les sorties réelles, pas des affirmations.

1. `curl /healthz` → `{"ok":true,"db":true,"mail":false}` tant que la boîte OVH n'existe pas.
2. `POST /v1/webhook/polar` signé → `5xx`, licence créée avec `emailed_at` nul.
3. Mêmes identifiants SMTP valides, rejeu du **même** `webhook-id` → `200`, email reçu,
   `emailed_at` renseigné, **toujours une seule licence**.
4. `POST /v1/resend-key` sur cette licence → second email, même clé, pas de nouvelle licence.
5. `DELETE /api/licenses/:id` → `204`, `total` décrémenté, `/v1/crl` sans l'identifiant.
6. `POST /api/licenses/purge {"confirm":"PURGE","filter":"test"}` → `total: 0`.

Tant que le point 3 n'est pas constaté dans une boîte réelle, le pipeline n'est pas terminé.
