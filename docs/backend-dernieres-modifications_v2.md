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


---

## M-03 — Publier une mise à jour depuis le dashboard

### Constat

Il n'existe **aucune gestion des versions** dans le dashboard : zéro occurrence de « release » dans
`src/public/index.html`, et aucune route `/api/releases`. Les seules routes d'administration sont
`/api/stats`, `/api/licenses`, `/api/licenses/:id/revoke`, `DELETE /api/licenses/:id` et
`/api/licenses/purge`.

Publier une version exige donc aujourd'hui une commande dans le conteneur :

```bash
docker cp rgaa-audit-0.2.2.zip rgaa-license-server:/keys/
docker exec rgaa-license-server node src/cli.js publish --zip /keys/rgaa-audit-0.2.2.zip --version 0.2.2
```

Pour l'éditeur du produit, c'est une friction à chaque sortie. L'objectif est un bouton
« Publier une version » dans l'onglet où il voit déjà ses licences.

### Spécification

**1. `POST /api/releases` — envoi direct du binaire, sans dépendance supplémentaire**

Utiliser `express.raw({ type: 'application/zip', limit: '50mb' })` plutôt que `multer` : cela évite
d'ajouter une dépendance, et un ZIP se transporte très bien en corps brut.

```
POST /api/releases?version=0.2.2&requires=6.5&tested=7.1&requires_php=8.1
Authorization: Bearer <ADMIN_TOKEN>
Content-Type: application/zip

<octets du fichier>
```

Traitement attendu :

1. vérifier que `version` ressemble à `X.Y.Z` → sinon `400` ;
2. **ouvrir le ZIP et lire `rgaa-audit/rgaa-audit.php`** : si le dossier racine n'est pas
   `rgaa-audit`, ou si l'en-tête `Version:` ne correspond pas au paramètre `version`, répondre
   `422 {"error":"version_mismatch","zip_version":"0.2.1","declared":"0.2.2"}`. Sans ce contrôle,
   on publie une archive dont le manifeste annonce une version qui n'est pas celle du code ;
3. écrire le fichier dans `<KEYS_DIR>/releases/rgaa-audit-<version>.zip` ;
4. calculer le SHA-256 **du fichier écrit** (relire sur disque, pas les octets en mémoire) ;
5. `db.createRelease({ version, zip_path, sha256, requires, tested, requires_php, changelog, published_at })` ;
6. **invalider le cache du manifeste** (sinon `/v1/updates` continue de servir l'ancienne version) ;
7. répondre `201 {"version":"0.2.2","sha256":"…","size":244814}`.

**2. `GET /api/releases`** — liste : version, sha256, taille, date de publication, nombre de
téléchargements, chemin.

**3. `DELETE /api/releases/:version`** — supprime la ligne et le fichier. Refuser de supprimer la
version la plus récente (`409 cannot_delete_latest`) : sinon un client reçoit un manifeste qui pointe
vers un 404.

**4. Dashboard — troisième onglet « Mises à jour »**

- un `<input type="file" accept=".zip">`, les champs `version`, `requires`, `tested`,
  `requires_php`, `changelog` (pré-remplis avec la version du ZIP une fois choisi) ;
- un bouton « Publier », qui affiche le SHA-256 retourné et le compare à celui du fichier local ;
- le tableau des versions publiées avec un bouton de suppression ;
- **afficher le SHA-256 en entier** : c'est la seule façon de vérifier qu'un fichier publié est le
  bon, et c'est ce que le plugin contrôle avant d'installer.

**5. Corriger la version en dur dans l'email**

`src/mailer.js` :

```js
const dlLink = downloadUrl || `${base}/v1/download/0.2.0.zip?key=${encodeURIComponent(key)}`;
```

`0.2.0` ne changera jamais. Le lien doit utiliser `db.getLatestRelease().version`, et si aucune
release n'existe, envoyer le mail **sans** lien de téléchargement plutôt qu'avec un lien mort.

### Critères d'acceptation

1. Envoi du ZIP 0.2.2 → `201`, fichier présent dans `<KEYS_DIR>/releases/`, `sha256` identique à
   `sha256sum` exécuté sur le fichier.
2. Envoi d'un ZIP dont l'en-tête `Version: 0.2.1` avec `?version=0.2.2` → `422 version_mismatch`,
   **aucun fichier écrit**.
3. `GET /v1/updates/rgaa-audit?key=…` immédiatement après → `"version":"0.2.2"` (pas d'attente de
   cache).
4. `GET /v1/download/0.2.2.zip?key=…` renvoie des octets dont le SHA-256 est celui du manifeste.
5. Le mail de licence contient un lien vers la version publiée, pas `0.2.0`.
6. `DELETE /api/releases/0.2.2` alors que c'est la dernière → `409`.


---

## M-04 — La version du lien de téléchargement vient de la base, jamais du code

### Constat

`src/mailer.js:53` :

```js
const dlLink = downloadUrl || `${base}/v1/download/0.2.0.zip?key=${encodeURIComponent(key)}`;
```

`0.2.0` est écrit en dur. La version 0.2.3 est publiée, mais tout acheteur reçoit un lien vers une
archive qui n'existe pas — et il faudra reconstruire l'image à chaque nouvelle version du plugin
pour corriger ça, ce qui n'est pas acceptable.

### Décision : pas de nouveau champ de configuration

Ajouter un champ « version » dans le dashboard serait une seconde source de vérité, qui dérivera de
la première : on publie 0.2.5, on oublie de mettre à jour le champ, et le mail pointe vers 0.2.4.
**La source de vérité existe déjà** : la table `releases`, alimentée par `POST /api/releases` ou par
la CLI `publish`. Le mail doit la lire au moment de l'envoi.

### Spécification

**1. Une seule fonction pour construire l'URL**, utilisée par le manifeste **et** par le mailer —
deux implémentations divergentes, c'est le défaut qui revient six mois plus tard :

```js
function buildDownloadUrl(key) {
  const release = db.getLatestRelease();
  if (!release) return null;                         // aucune version publiée

  const base = release.download_url
    ? release.download_url.replace(/\?.*$/, '')      // URL déclarée à la publication
    : `${config.publicBaseUrl}/v1/download/${release.version}.zip`;

  return key ? `${base}?key=${encodeURIComponent(key)}` : base;
}
```

**2. Le handler passe l'URL au mailer** (les deux appels : achat et renouvellement) :

```js
const downloadUrl = buildDownloadUrl(signed.key);
sendLicenseEmail({ to: email, plan, domain, expires, key: signed.key, downloadUrl });
```

**3. Aucun lien mort.** Si `buildDownloadUrl()` renvoie `null`, le corps de l'email **omet** le bloc
de téléchargement. Un email sans lien est gênant ; un lien vers un 404 est un ticket de support et
un client qui doute du produit.

**4. Afficher la version dans le texte** : « Télécharger la version 0.2.3 (.zip) » — le client sait
ce qu'il installe, et le support sait ce qu'il doit demander.

**5. Même traitement dans l'email de renouvellement** (`isRenewal: true`), qui utilise le même
`dlLink`.

**6. `grep -rn "0\.2\.\d" src/`** ne doit plus renvoyer de version en dur dans du code exécutable
(les exemples de README et les tests sont exclus).

### Critères d'acceptation

1. Release 0.2.3 publiée, achat test → l'email contient `/v1/download/0.2.3.zip` et ce lien renvoie
   `200` avec le SHA-256 du manifeste.
2. Base vidée de ses releases → l'email part **sans** bloc de téléchargement, en `200`, sans erreur.
3. Publier 0.2.4 par `POST /api/releases` **sans redémarrer le conteneur** → l'email suivant pointe
   sur 0.2.4. Aucune reconstruction d'image, aucun redémarrage.
4. Le renouvellement envoie le même lien à jour.
